// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E proof that the managed loopback proxy accepts inside the sandbox
//! network namespace but dispatches upstream dialing from the supervisor side.

#![cfg(feature = "e2e-host-gateway")]

use std::io::Write;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const TEST_HOST: &str = "host.openshell.internal";

struct HostServer {
    port: u16,
    task: JoinHandle<()>,
}

impl HostServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("bind host test server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read host test server address: {e}"))?
            .port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let body = br#"{"message":"loopback-supervisor-dispatch-ok"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Ok(Self { port, task })
    }
}

impl Drop for HostServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn write_policy(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  loopback_proxy_netns:
    name: loopback_proxy_netns
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

fn netns_boundary_script(port: u16) -> String {
    format!(
        r#"
import json
import os
import socket
import urllib.parse

HOST = {TEST_HOST:?}
PORT = {port}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def read_response(sock):
    response = recv_until(sock, b"\r\n\r\n")
    headers, _, body = response.partition(b"\r\n\r\n")
    content_length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return response.decode("iso-8859-1", "replace"), body.decode("utf-8", "replace")

def direct_connect_result():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((HOST, PORT))
        sock.sendall(f"GET /direct HTTP/1.1\r\nHost: {{HOST}}:{{PORT}}\r\nConnection: close\r\n\r\n".encode("ascii"))
        response, body = read_response(sock)
        return {{"result": "connected", "response": response.splitlines()[0] if response else "", "body": body}}
    except ConnectionRefusedError as error:
        return {{"result": "refused", "error": str(error)}}
    except socket.timeout as error:
        return {{"result": "timeout", "error": str(error)}}
    except OSError as error:
        return {{"result": "error", "errno": error.errno, "error": str(error)}}
    finally:
        sock.close()

def loopback_connect_result():
    proxy_url = os.environ.get("OPENSHELL_LOOPBACK_PROXY_URL")
    if not proxy_url:
        return {{"result": "missing_proxy_url"}}
    parsed = urllib.parse.urlparse(proxy_url)
    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        return {{"result": "non_loopback_proxy_url", "proxy_url": proxy_url}}

    target = f"{{HOST}}:{{PORT}}"
    with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
        sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode("ascii"))
        connect_response = recv_until(sock, b"\r\n\r\n").decode("iso-8859-1", "replace")
        if not (connect_response.startswith("HTTP/1.1 200") or connect_response.startswith("HTTP/1.0 200")):
            return {{"result": "connect_failed", "response": connect_response.splitlines()[0] if connect_response else ""}}
        sock.sendall(f"GET /proxied HTTP/1.1\r\nHost: {{target}}\r\nConnection: close\r\n\r\n".encode("ascii"))
        response, body = read_response(sock)
        return {{"result": "ok", "response": response.splitlines()[0] if response else "", "body": body}}

print(json.dumps({{
    "direct": direct_connect_result(),
    "loopback": loopback_connect_result(),
}}, sort_keys=True), flush=True)
"#
    )
}

#[tokio::test]
async fn loopback_proxy_connect_uses_supervisor_namespace_for_upstream_dial() {
    let server = HostServer::start().await.expect("start host test server");
    let policy = write_policy(server.port).expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();
    let script = netns_boundary_script(server.port);

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");

    let output = guard
        .create_output
        .lines()
        .find(|line| line.contains("\"direct\"") && line.contains("\"loopback\""))
        .unwrap_or_else(|| {
            panic!(
                "expected netns boundary JSON in output:\n{}",
                guard.create_output
            )
        });
    let parsed: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|err| panic!("failed to parse JSON '{output}': {err}"));

    assert_eq!(
        parsed["direct"]["result"], "refused",
        "expected direct sandbox egress to be rejected before reaching host server:\n{}",
        guard.create_output
    );
    assert_eq!(
        parsed["loopback"]["result"], "ok",
        "expected CONNECT through OPENSHELL_LOOPBACK_PROXY_URL to reach host server:\n{}",
        guard.create_output
    );
    assert_eq!(
        parsed["loopback"]["body"], r#"{"message":"loopback-supervisor-dispatch-ok"}"#,
        "expected loopback proxy path to receive host server response:\n{}",
        guard.create_output
    );
}
