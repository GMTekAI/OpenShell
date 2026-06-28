// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared HTTP/1.1 request helpers for L7 protocols carried over HTTP.

use crate::l7::provider::{BodyLength, L7Request};
use miette::{IntoDiagnostic, Result, miette};
use tokio::io::{AsyncRead, AsyncReadExt};

const READ_BUF_SIZE: usize = 8192;

/// Validate the HTTP/1.1 `Host` authority before any credential-bearing
/// request bytes are written upstream.
///
/// Credential rewriting is target-bound. Requiring exactly one canonical
/// `Host` prevents a request from selecting policy and credentials with the
/// CONNECT or absolute-form target while directing a permissive upstream
/// parser at a different authority.
pub fn validate_bound_host_header(
    raw_headers: &[u8],
    expected_host: &str,
    expected_port: u16,
    default_port: u16,
) -> Result<()> {
    validate_http1_request_head(raw_headers)?;
    let header_end = raw_headers
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| miette!("HTTP headers missing terminator"))?;
    let headers = std::str::from_utf8(&raw_headers[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;

    let mut host_value = None;
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(miette!("HTTP Host validation rejects folded headers"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(miette!("HTTP header is missing ':' separator"));
        };
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(miette!(
                "credential-bearing request contains an invalid HTTP header name"
            ));
        }
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        if host_value.replace(value.trim()).is_some() {
            return Err(miette!(
                "credential rewrite requires exactly one Host header"
            ));
        }
    }

    let host_value = host_value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| miette!("credential rewrite requires exactly one Host header"))?;
    if host_value.contains('@') {
        return Err(miette!("Host header must not contain userinfo"));
    }
    let authority = host_value
        .parse::<http::uri::Authority>()
        .map_err(|_| miette!("Host header contains an invalid authority"))?;
    let actual_host = normalize_host(authority.host())?;
    let expected_host = normalize_host(expected_host)?;
    if actual_host != expected_host {
        return Err(miette!(
            "Host header does not match the policy-bound target host"
        ));
    }

    let actual_port = match authority.port_u16() {
        Some(port) if port > 0 => port,
        Some(_) => return Err(miette!("Host header port must be greater than zero")),
        None if default_port > 0 => default_port,
        None => {
            return Err(miette!(
                "Host header must include a port for a non-default target"
            ));
        }
    };
    if actual_port != expected_port {
        return Err(miette!(
            "Host header does not match the policy-bound target port"
        ));
    }

    Ok(())
}

pub fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Validate the HTTP/1 request line and header grammar before any
/// credential-bearing bytes can be rewritten or forwarded. This deliberately
/// rejects obsolete folding and whitespace before `:` so upstream parsers
/// cannot reinterpret a header that the policy parser ignored.
pub fn validate_http1_request_head(raw: &[u8]) -> Result<()> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| miette!("HTTP headers missing terminator"))?;
    let head = &raw[..header_end];
    for (index, byte) in head.iter().copied().enumerate() {
        if byte == 0 || byte == 0x7f || (byte < 0x20 && !matches!(byte, b'\r' | b'\n' | b'\t')) {
            return Err(miette!(
                "HTTP request head contains a forbidden control byte"
            ));
        }
        if byte == b'\r' && head.get(index + 1) != Some(&b'\n') {
            return Err(miette!("HTTP request head contains bare carriage return"));
        }
        if byte == b'\n' && (index == 0 || head[index - 1] != b'\r') {
            return Err(miette!("HTTP request head contains bare line feed"));
        }
    }
    let head =
        std::str::from_utf8(head).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| miette!("HTTP request line is missing"))?;
    if request_line.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(miette!("HTTP request line contains a control byte"));
    }
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(miette!(
            "HTTP request line must contain exactly method, target, and version separated by single spaces"
        ));
    }
    if !parts[0].bytes().all(is_http_token_byte) {
        return Err(miette!("HTTP method is not a valid token"));
    }
    if !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(miette!("Unsupported HTTP version: {}", parts[2]));
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            return Err(miette!(
                "HTTP request head contains an obsolete folded header"
            ));
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(miette!("HTTP header is missing ':' separator"));
        };
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(miette!("HTTP header name is not a valid token"));
        }
    }
    Ok(())
}

/// Credential-bearing requests carried inside a CONNECT tunnel must use
/// origin-form. An absolute-form authority can otherwise disagree with the
/// CONNECT/Host authority and be honored by an upstream proxy.
pub fn validate_origin_form_request_target(raw_headers: &[u8]) -> Result<()> {
    validate_http1_request_head(raw_headers)?;
    let request_line_end = raw_headers
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| miette!("HTTP request line missing terminator"))?;
    let request_line = std::str::from_utf8(&raw_headers[..request_line_end])
        .map_err(|_| miette!("HTTP request line contains invalid UTF-8"))?;
    let mut parts = request_line.split(' ');
    let _method = parts
        .next()
        .ok_or_else(|| miette!("HTTP request line is missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| miette!("HTTP request line is missing target"))?;
    let _version = parts
        .next()
        .ok_or_else(|| miette!("HTTP request line is missing version"))?;
    if parts.next().is_some() || !target.starts_with('/') || target.starts_with("//") {
        return Err(miette!(
            "credential rewrite requires an origin-form HTTP request target"
        ));
    }
    Ok(())
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty()
        || host.contains('/')
        || host.contains('\\')
        || host.contains('?')
        || host.contains('#')
    {
        return Err(miette!("target host is not a valid HTTP authority host"));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    Ok(host.trim_end_matches('.').to_ascii_lowercase())
}

pub fn has_query_delimiter(target: &str) -> bool {
    target.contains('?')
}

pub async fn read_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    let overflow = request.raw_header[header_end..].to_vec();

    match request.body_length {
        BodyLength::None => Ok(Vec::new()),
        BodyLength::ContentLength(len) => {
            let len = usize::try_from(len)
                .map_err(|_| miette!("HTTP request body length exceeds platform limit"))?;
            if len > max_body_bytes {
                return Err(miette!(
                    "HTTP request body exceeds {max_body_bytes} byte inspection limit"
                ));
            }
            if overflow.len() > len {
                return Err(miette!(
                    "HTTP request contains more body bytes than Content-Length"
                ));
            }
            let remaining = len - overflow.len();
            let mut body = overflow;
            if remaining > 0 {
                let start = body.len();
                body.resize(len, 0);
                client
                    .read_exact(&mut body[start..])
                    .await
                    .into_diagnostic()?;
            }
            request.raw_header.truncate(header_end);
            request.raw_header.extend_from_slice(&body);
            Ok(body)
        }
        BodyLength::Chunked => {
            let body = read_chunked_body_for_inspection(
                client,
                request,
                header_end,
                overflow,
                max_body_bytes,
            )
            .await?;
            normalize_chunked_request_to_content_length(request, header_end, &body)?;
            Ok(body)
        }
    }
}

fn normalize_chunked_request_to_content_length(
    request: &mut L7Request,
    header_end: usize,
    body: &[u8],
) -> Result<()> {
    let header_str = std::str::from_utf8(&request.raw_header[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let header_str = header_str
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| miette!("HTTP headers missing terminator"))?;

    let mut normalized = Vec::with_capacity(header_str.len() + body.len() + 32);
    for (idx, line) in header_str.split("\r\n").enumerate() {
        if idx > 0 {
            let name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase());
            if matches!(
                name.as_deref(),
                Some("transfer-encoding" | "content-length" | "trailer")
            ) {
                continue;
            }
        }
        normalized.extend_from_slice(line.as_bytes());
        normalized.extend_from_slice(b"\r\n");
    }
    normalized.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    normalized.extend_from_slice(body);

    request.raw_header = normalized;
    request.body_length = BodyLength::ContentLength(body.len() as u64);
    Ok(())
}

async fn read_chunked_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    header_end: usize,
    overflow: Vec<u8>,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let mut raw = overflow;
    let mut decoded = Vec::new();
    let mut pos = 0usize;

    loop {
        let size_line_end = loop {
            if let Some(end) = find_crlf(&raw, pos) {
                break end;
            }
            read_more(client, &mut raw, max_body_bytes).await?;
        };
        let size_line = std::str::from_utf8(&raw[pos..size_line_end])
            .into_diagnostic()
            .map_err(|_| miette!("Invalid UTF-8 in HTTP chunk-size line"))?;
        let size_token = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .into_diagnostic()
            .map_err(|_| miette!("Invalid HTTP chunk size token: {size_token:?}"))?;
        pos = size_line_end + 2;

        if decoded.len().saturating_add(chunk_size) > max_body_bytes {
            return Err(miette!(
                "HTTP request body exceeds {max_body_bytes} byte inspection limit"
            ));
        }

        if chunk_size == 0 {
            loop {
                let trailer_end = loop {
                    if let Some(end) = find_crlf(&raw, pos) {
                        break end;
                    }
                    read_more(client, &mut raw, max_body_bytes).await?;
                };
                let trailer_line = &raw[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    request.raw_header.truncate(header_end);
                    request.raw_header.extend_from_slice(&raw[..pos]);
                    return Ok(decoded);
                }
            }
        }

        let chunk_end = pos
            .checked_add(chunk_size)
            .ok_or_else(|| miette!("HTTP chunk size overflow"))?;
        let chunk_with_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| miette!("HTTP chunk size overflow"))?;
        while raw.len() < chunk_with_crlf_end {
            read_more(client, &mut raw, max_body_bytes).await?;
        }
        decoded.extend_from_slice(&raw[pos..chunk_end]);
        if raw.get(chunk_end..chunk_with_crlf_end) != Some(&b"\r\n"[..]) {
            return Err(miette!("HTTP chunk payload missing terminating CRLF"));
        }
        pos = chunk_with_crlf_end;
    }
}

async fn read_more<C: AsyncRead + Unpin>(
    client: &mut C,
    raw: &mut Vec<u8>,
    max_body_bytes: usize,
) -> Result<()> {
    if raw.len() > max_body_bytes.saturating_mul(2).max(max_body_bytes) {
        return Err(miette!(
            "HTTP chunked request body exceeds inspection framing limit"
        ));
    }
    let mut buf = [0u8; READ_BUF_SIZE];
    let n = client.read(&mut buf).await.into_diagnostic()?;
    if n == 0 {
        return Err(miette!("HTTP chunked body ended before terminator"));
    }
    raw.extend_from_slice(&buf[..n]);
    Ok(())
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_host_accepts_normalized_dns_and_default_port() {
        validate_bound_host_header(
            b"POST /mcp HTTP/1.1\r\nHost: MCP.Example.Test.\r\n\r\n",
            "mcp.example.test",
            443,
            443,
        )
        .unwrap();
    }

    #[test]
    fn bound_host_accepts_canonical_ipv6() {
        validate_bound_host_header(
            b"POST /mcp HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
            "2001:0db8:0:0:0:0:0:1",
            8443,
            0,
        )
        .unwrap();
    }

    #[test]
    fn bound_host_rejects_missing_duplicate_and_mismatch() {
        for raw in [
            &b"POST /mcp HTTP/1.1\r\nContent-Length: 0\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\nhost: mcp.example.test\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: attacker.example\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test:8443\r\n\r\n"[..],
        ] {
            assert!(
                validate_bound_host_header(raw, "mcp.example.test", 443, 443).is_err(),
                "invalid Host binding should be rejected: {:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn bound_host_rejects_bad_whitespace_and_invalid_field_names() {
        for raw in [
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\nHost : attacker.example\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\nHost\t: attacker.example\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\nBad Name: value\r\n\r\n"[..],
            &b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n continuation\r\n\r\n"[..],
        ] {
            assert!(
                validate_bound_host_header(raw, "mcp.example.test", 443, 443).is_err(),
                "malformed field name must be rejected: {:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn bound_host_requires_explicit_non_default_port() {
        assert!(
            validate_bound_host_header(
                b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n",
                "mcp.example.test",
                8443,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn https_default_port_is_443_even_when_connect_targets_port_80() {
        assert!(
            validate_bound_host_header(
                b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n",
                "mcp.example.test",
                80,
                443,
            )
            .is_err()
        );
        validate_bound_host_header(
            b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test:80\r\n\r\n",
            "mcp.example.test",
            80,
            443,
        )
        .unwrap();
        validate_bound_host_header(
            b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n",
            "mcp.example.test",
            443,
            443,
        )
        .unwrap();
    }

    #[test]
    fn detects_any_query_delimiter() {
        assert!(has_query_delimiter("/mcp?token=x"));
        assert!(has_query_delimiter("/mcp?"));
        assert!(!has_query_delimiter("/mcp"));
    }

    #[test]
    fn credential_target_rejects_absolute_and_authority_forms() {
        for raw in [
            &b"POST https://attacker.example/mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n"[..],
            &b"CONNECT attacker.example:443 HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n"[..],
            &b"POST //attacker.example/mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n"[..],
        ] {
            assert!(validate_origin_form_request_target(raw).is_err());
        }
        validate_origin_form_request_target(
            b"POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n",
        )
        .unwrap();
    }
}
