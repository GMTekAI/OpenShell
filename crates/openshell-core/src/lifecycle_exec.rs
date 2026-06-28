// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Closed registry of compiled fixed-path supervisor lifecycle operations.
//!
//! Policy grants stable operation IDs, never arbitrary executable paths. Both
//! the gateway and sandbox supervisor resolve and validate the same compiled
//! specification before a maintenance process can start.
//!
//! Root ownership, non-writability, and FD pinning prevent replacement by the
//! running workload. They do not establish image provenance or code signing;
//! the lifecycle child receives exactly the ordinary workload authority.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

pub const NEMOCLAW_HERMES_MCP_CONFIG_OPERATION: &str = "nemoclaw.hermes-mcp-config-transaction-v1";
pub const NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE: &str =
    "/usr/local/lib/nemoclaw/hermes-mcp-config-transaction.py";
/// Environment variable containing the inherited Unix socket capability FD.
///
/// The value is not secret; authenticity comes from `SO_PEERCRED` on the
/// connected root-owned supervisor peer and the exact operation handshake.
pub const LIFECYCLE_AUTH_FD_ENV: &str = "OPENSHELL_LIFECYCLE_AUTH_FD";
pub const NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE: &[u8] =
    b"openshell-lifecycle-auth-v1:nemoclaw.hermes-mcp-config-transaction-v1\n";
/// Lifecycle operations must always be bounded. The `NemoClaw` transaction uses
/// 620 seconds so this leaves a small, explicit margin without permitting an
/// unbounded maintenance child.
pub const MAX_LIFECYCLE_TIMEOUT_SECONDS: u32 = 900;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleOperationSpec {
    pub id: &'static str,
    pub executable: &'static str,
}

pub const NEMOCLAW_HERMES_MCP_CONFIG_SPEC: LifecycleOperationSpec = LifecycleOperationSpec {
    id: NEMOCLAW_HERMES_MCP_CONFIG_OPERATION,
    executable: NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE,
};

pub fn operation_by_id(id: &str) -> Option<&'static LifecycleOperationSpec> {
    (id == NEMOCLAW_HERMES_MCP_CONFIG_OPERATION).then_some(&NEMOCLAW_HERMES_MCP_CONFIG_SPEC)
}

pub fn operation_for_command(command: &[String]) -> Option<&'static LifecycleOperationSpec> {
    let executable = command.first()?;
    (Path::new(executable) == Path::new(NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE))
        .then_some(&NEMOCLAW_HERMES_MCP_CONFIG_SPEC)
}

/// Validate the complete argv contract for a compiled fixed-path operation.
///
/// Hermes accepts exactly `probe` or `add|remove --payload <JSON object>`. The helper
/// performs the semantic field validation; this boundary rejects alternate
/// programs, switches, and interpreter-style arbitrary code before exec.
pub fn validate_operation_command(
    spec: &LifecycleOperationSpec,
    command: &[String],
) -> Result<(), &'static str> {
    if spec != &NEMOCLAW_HERMES_MCP_CONFIG_SPEC {
        return Err("unknown lifecycle operation");
    }
    if command.first().map(String::as_str) != Some(spec.executable) {
        return Err("lifecycle operation argv does not match the compiled executable contract");
    }
    if command.len() == 2 && command[1] == "probe" {
        return Ok(());
    }
    if command.len() != 4 {
        return Err("lifecycle operation argv does not match the compiled executable contract");
    }
    if !matches!(command[1].as_str(), "add" | "remove") || command[2] != "--payload" {
        return Err("lifecycle operation argv does not match an allowed action");
    }
    let payload: serde_json::Value =
        serde_json::from_str(&command[3]).map_err(|_| "lifecycle payload is not valid JSON")?;
    validate_hermes_payload(command[1].as_str(), &payload)?;
    Ok(())
}

fn validate_hermes_payload(action: &str, payload: &serde_json::Value) -> Result<(), &'static str> {
    let object = payload
        .as_object()
        .ok_or("lifecycle payload must be a JSON object")?;
    let mut allowed = BTreeSet::from(["server", "url", "headers"]);
    allowed.insert(if action == "add" {
        "replace_existing"
    } else {
        "force"
    });
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err("lifecycle payload contains an unsupported field");
    }

    let server = object
        .get("server")
        .and_then(serde_json::Value::as_str)
        .ok_or("lifecycle payload server is required")?;
    if server.is_empty()
        || server.len() > 64
        || !server.as_bytes()[0].is_ascii_alphabetic()
        || !server
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("lifecycle payload server is invalid");
    }

    let raw_url = object
        .get("url")
        .and_then(serde_json::Value::as_str)
        .ok_or("lifecycle payload URL is required")?;
    if raw_url.len() > 2048 {
        return Err("lifecycle payload URL is too long");
    }
    let url = url::Url::parse(raw_url).map_err(|_| "lifecycle payload URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("lifecycle payload URL is not canonical HTTPS");
    }
    let hostname = url
        .host_str()
        .ok_or("lifecycle payload URL host is required")?
        .to_ascii_lowercase();
    let hostname = hostname.trim_end_matches('.');
    if hostname.contains(':') {
        return Err("lifecycle payload URL IPv6 literals are not supported");
    }
    if !hostname.is_ascii()
        || hostname
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b';'))
    {
        return Err("lifecycle payload URL host must be literal");
    }
    if url.port() == Some(0) {
        return Err("lifecycle payload URL port must be nonzero");
    }
    let host_alias = matches!(
        hostname,
        "host.openshell.internal" | "host.docker.internal" | "host.containers.internal"
    );
    if !host_alias
        && (["localhost", "local", "internal", "metadata"]
            .iter()
            .any(|suffix| hostname == *suffix || hostname.ends_with(&format!(".{suffix}"))))
    {
        return Err("lifecycle payload URL uses a reserved hostname");
    }
    if let Ok(address) = hostname.parse::<Ipv4Addr>() {
        if BLOCKED_IPV4_NETWORKS
            .iter()
            .any(|(network, prefix)| ipv4_in_network(address, *network, *prefix))
        {
            return Err("lifecycle payload URL uses a non-global address");
        }
    } else if is_ambiguous_numeric_host(hostname) {
        return Err("lifecycle payload URL uses an ambiguous numeric host");
    }
    let path = url.path();
    if !path.starts_with('/')
        || path.bytes().any(|byte| {
            matches!(
                byte,
                b'%' | b'\\' | b';' | b'*' | b'?' | b'[' | b']' | b'{' | b'}'
            )
        })
    {
        return Err("lifecycle payload URL path must be literal and canonical");
    }
    let authority = url
        .port()
        .map_or_else(|| hostname.to_string(), |port| format!("{hostname}:{port}"));
    let canonical = format!("https://{authority}{path}");
    if raw_url != canonical {
        return Err("lifecycle payload URL must be canonical");
    }

    let headers = object
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .ok_or("lifecycle payload headers are required")?;
    if headers.len() != 1 {
        return Err("lifecycle payload must contain one Authorization header");
    }
    let authorization = headers
        .get("Authorization")
        .and_then(serde_json::Value::as_str)
        .ok_or("lifecycle payload Authorization header is required")?;
    let key = authorization
        .strip_prefix("Bearer openshell:resolve:env:")
        .ok_or("lifecycle payload Authorization must use an OpenShell placeholder")?;
    if key.is_empty()
        || key.len() > 128
        || !(key.as_bytes()[0].is_ascii_alphabetic() || key.as_bytes()[0] == b'_')
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("lifecycle payload credential placeholder is invalid");
    }

    let flag = if action == "add" {
        "replace_existing"
    } else {
        "force"
    };
    if !object.get(flag).is_some_and(serde_json::Value::is_boolean) {
        return Err("lifecycle payload control flag must be boolean");
    }
    Ok(())
}

const BLOCKED_IPV4_NETWORKS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::UNSPECIFIED, 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 31, 196, 0), 24),
    (Ipv4Addr::new(192, 52, 193, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(192, 175, 48, 0), 24),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

fn ipv4_in_network(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    u32::from(address) & mask == u32::from(network) & mask
}

fn is_ambiguous_numeric_host(host: &str) -> bool {
    let mut saw_component = false;
    for component in host.split('.') {
        if component.is_empty() {
            return false;
        }
        saw_component = true;
        let digits = component
            .strip_prefix("0x")
            .or_else(|| component.strip_prefix("0X"))
            .unwrap_or(component);
        if digits.is_empty()
            || !digits.bytes().all(|byte| {
                if component.starts_with("0x") || component.starts_with("0X") {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
            })
        {
            return false;
        }
    }
    saw_component
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_operation_rejects_interpreters_and_alternate_argv() {
        let valid = vec![
            NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
            "add".to_string(),
            "--payload".to_string(),
            r#"{"server":"demo","url":"https://mcp.example.test/mcp","headers":{"Authorization":"Bearer openshell:resolve:env:DEMO_TOKEN"},"replace_existing":false}"#.to_string(),
        ];
        let spec = operation_for_command(&valid).expect("compiled operation");
        assert!(validate_operation_command(spec, &valid).is_ok());

        let mut interpreter = valid.clone();
        interpreter[0] = "/opt/hermes/.venv/bin/python".to_string();
        assert!(operation_for_command(&interpreter).is_none());

        let mut alternate_action = valid;
        alternate_action[1] = "--help".to_string();
        assert!(validate_operation_command(spec, &alternate_action).is_err());

        let probe = vec![
            NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
            "probe".to_string(),
        ];
        assert!(validate_operation_command(spec, &probe).is_ok());
        let mut probe_with_payload = probe;
        probe_with_payload.push("--payload".to_string());
        assert!(validate_operation_command(spec, &probe_with_payload).is_err());
    }

    #[test]
    fn hermes_operation_rejects_noncanonical_or_private_targets() {
        let rejected = [
            "https://localhost/mcp",
            "https://127.0.0.1/mcp",
            "https://10.0.0.1/mcp",
            "https://[2001:4860:4860::8888]/mcp",
            "https://2130706433/mcp",
            "https://mcp.example.test:443/mcp",
            "https://MCP.EXAMPLE.TEST/mcp",
            "https://mcp.example.test/mcp%2fadmin",
            "https://mcp.example.test/mcp;admin",
            "https://mcp.example.test/mcp*",
        ];
        for url in rejected {
            let command = vec![
                NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
                "add".to_string(),
                "--payload".to_string(),
                serde_json::json!({
                    "server": "demo",
                    "url": url,
                    "headers": {"Authorization": "Bearer openshell:resolve:env:DEMO_TOKEN"},
                    "replace_existing": false,
                })
                .to_string(),
            ];
            assert!(
                validate_operation_command(&NEMOCLAW_HERMES_MCP_CONFIG_SPEC, &command).is_err(),
                "unexpectedly accepted {url}"
            );
        }
    }

    #[test]
    fn hermes_operation_requires_typed_control_flag() {
        for payload in [
            serde_json::json!({
                "server": "demo",
                "url": "https://mcp.example.test/mcp",
                "headers": {"Authorization": "Bearer openshell:resolve:env:DEMO_TOKEN"},
            }),
            serde_json::json!({
                "server": "demo",
                "url": "https://mcp.example.test/mcp",
                "headers": {"Authorization": "Bearer openshell:resolve:env:DEMO_TOKEN"},
                "replace_existing": "false",
            }),
        ] {
            let command = vec![
                NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
                "add".to_string(),
                "--payload".to_string(),
                payload.to_string(),
            ];
            assert!(
                validate_operation_command(&NEMOCLAW_HERMES_MCP_CONFIG_SPEC, &command).is_err()
            );
        }
    }
}
