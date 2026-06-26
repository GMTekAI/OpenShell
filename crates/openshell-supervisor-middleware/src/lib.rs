// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process supervisor middleware chain execution.

mod builtins;
mod service;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use miette::{Result, miette};
pub use service::InProcessMiddlewareService;

use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestTarget, NetworkMiddlewareConfig, Process,
    RequestContext,
};
use tonic::Request;

pub const API_VERSION: &str = "openshell.middleware.v1";
pub const HTTP_REQUEST_OPERATION: &str = "HttpRequest";
pub const PRE_CREDENTIALS_PHASE: &str = "pre_credentials";
pub const BUILTIN_SECRETS: &str = "openshell/secrets";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    FailClosed,
    FailOpen,
}

impl OnError {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "fail_closed" => Ok(Self::FailClosed),
            "fail_open" => Ok(Self::FailOpen),
            other => Err(miette!(
                "invalid middleware on_error '{other}', expected fail_closed or fail_open"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub implementation: String,
    pub config: prost_types::Struct,
    pub on_error: OnError,
}

impl TryFrom<&NetworkMiddlewareConfig> for ChainEntry {
    type Error = miette::Report;

    fn try_from(value: &NetworkMiddlewareConfig) -> Result<Self> {
        if value.name.is_empty() {
            return Err(miette!("middleware config name cannot be empty"));
        }
        if value.middleware.is_empty() {
            return Err(miette!(
                "middleware config '{}' must name an implementation",
                value.name
            ));
        }
        Ok(Self {
            name: value.name.clone(),
            implementation: value.middleware.clone(),
            config: value.config.clone().unwrap_or_default(),
            on_error: OnError::parse(&value.on_error)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub binary: String,
    pub pid: u32,
    pub ancestors: Vec<String>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChainOutcome {
    pub allowed: bool,
    pub reason: String,
    pub body: Vec<u8>,
    pub added_headers: BTreeMap<String, String>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub applied: Vec<MiddlewareInvocation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamespacedFinding {
    pub middleware: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareInvocation {
    pub name: String,
    pub implementation: String,
    pub decision: Decision,
    pub transformed: bool,
}

#[derive(Clone)]
pub struct ChainRunner {
    service: Arc<dyn SupervisorMiddleware>,
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self::new(Arc::new(InProcessMiddlewareService))
    }
}

impl ChainRunner {
    pub fn new(service: Arc<dyn SupervisorMiddleware>) -> Self {
        Self { service }
    }

    pub async fn evaluate(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        let mut headers = input.headers.clone();
        let mut body = input.body.clone();
        let mut added_headers = BTreeMap::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();

        for entry in entries {
            let evaluation = build_evaluation(entry, &input, &headers, &body);
            let result = match self
                .service
                .evaluate_http_request(Request::new(evaluation))
                .await
            {
                Ok(result) => result.into_inner(),
                Err(err) => match entry.on_error {
                    OnError::FailOpen => {
                        applied.push(MiddlewareInvocation {
                            name: entry.name.clone(),
                            implementation: entry.implementation.clone(),
                            decision: Decision::Allow,
                            transformed: false,
                        });
                        continue;
                    }
                    OnError::FailClosed => {
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason: format!("middleware_failed: {}", safe_reason(&err.to_string())),
                            body,
                            added_headers,
                            findings,
                            metadata,
                            applied,
                        });
                    }
                },
            };

            validate_header_mutations(&headers, &result.add_headers)?;
            for (name, value) in &result.add_headers {
                headers.insert(name.to_ascii_lowercase(), value.clone());
                added_headers.insert(name.to_ascii_lowercase(), value.clone());
            }
            let transformed = result.has_body;
            if result.has_body {
                body = result.body.clone();
            }
            for finding in result.findings {
                findings.push(NamespacedFinding {
                    middleware: entry.name.clone(),
                    finding,
                });
            }
            if !result.metadata.is_empty() {
                metadata.insert(
                    entry.name.clone(),
                    result.metadata.clone().into_iter().collect(),
                );
            }
            applied.push(MiddlewareInvocation {
                name: entry.name.clone(),
                implementation: entry.implementation.clone(),
                decision: Decision::try_from(result.decision).unwrap_or(Decision::Unspecified),
                transformed,
            });
            if result.decision == Decision::Deny as i32 {
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: safe_reason(&result.reason),
                    body,
                    added_headers,
                    findings,
                    metadata,
                    applied,
                });
            }
        }

        Ok(ChainOutcome {
            allowed: true,
            reason: String::new(),
            body,
            added_headers,
            findings,
            metadata,
            applied,
        })
    }
}

fn build_evaluation(
    entry: &ChainEntry,
    input: &HttpRequestInput,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        api_version: API_VERSION.into(),
        binding_id: entry.implementation.clone(),
        phase: PRE_CREDENTIALS_PHASE.into(),
        context: Some(RequestContext {
            request_id: input.request_id.clone(),
            sandbox_id: input.sandbox_id.clone(),
            originating_process: Some(Process {
                binary: input.binary.clone(),
                pid: input.pid,
                ancestors: input.ancestors.clone(),
            }),
        }),
        config: Some(entry.config.clone()),
        target: Some(HttpRequestTarget {
            scheme: input.scheme.clone(),
            host: input.host.clone(),
            port: u32::from(input.port),
            method: input.method.clone(),
            path: input.path.clone(),
            query: input.query.clone(),
        }),
        headers: headers.clone().into_iter().collect(),
        body: body.to_vec(),
    }
}

fn validate_header_mutations(
    existing_headers: &BTreeMap<String, String>,
    mutations: &HashMap<String, String>,
) -> Result<()> {
    let mut seen = HashSet::new();
    for name in mutations.keys() {
        let lower = name.to_ascii_lowercase();
        if !seen.insert(lower.clone()) || existing_headers.contains_key(&lower) {
            return Err(miette!(
                "middleware cannot rewrite existing header '{name}'"
            ));
        }
        if !is_safe_append_header(&lower) {
            return Err(miette!("middleware cannot append unsafe header '{name}'"));
        }
    }
    Ok(())
}

fn is_safe_append_header(name: &str) -> bool {
    if name.is_empty()
        || name.contains(':')
        || name.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || matches!(
            name,
            "authorization" | "cookie" | "host" | "content-length" | "transfer-encoding"
        )
        || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
    {
        return false;
    }
    name.starts_with("x-openshell-middleware-")
}

pub(crate) fn safe_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | ' '))
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;

    fn entry(name: &str, on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: BUILTIN_SECRETS.into(),
            config: prost_types::Struct {
                fields: [(
                    "secrets".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("redact".into())),
                    },
                )]
                .into_iter()
                .collect(),
            },
            on_error,
        }
    }

    fn input(body: &str) -> HttpRequestInput {
        HttpRequestInput {
            request_id: "req".into(),
            sandbox_id: "sbx".into(),
            binary: "/usr/bin/curl".into(),
            pid: 42,
            ancestors: vec![],
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1".into(),
            query: String::new(),
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn redacts_common_secret_patterns() {
        let outcome = ChainRunner::default()
            .evaluate(
                &[entry("redact", OnError::FailClosed)],
                input(r#"{"api_key":"sk-1234567890abcdef"}"#),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"{"api_key":"[REDACTED]"}"#
        );
        assert_eq!(outcome.findings[0].finding.count, 1);
    }

    #[tokio::test]
    async fn transformed_body_feeds_next_stage() {
        let entries = [
            entry("first", OnError::FailClosed),
            entry("second", OnError::FailClosed),
        ];
        let outcome = ChainRunner::default()
            .evaluate(&entries, input(r#"password="top-secret""#))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"password="[REDACTED]""#
        );
        assert_eq!(outcome.applied.len(), 2);
    }

    #[tokio::test]
    async fn fail_open_allows_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let outcome = ChainRunner::default()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
    }

    #[tokio::test]
    async fn fail_closed_denies_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let outcome = ChainRunner::default()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
    }

    #[tokio::test]
    async fn in_process_service_describes_builtin_binding() {
        let manifest = InProcessMiddlewareService
            .describe(Request::new(()))
            .await
            .expect("describe")
            .into_inner();
        assert_eq!(manifest.api_version, API_VERSION);
        assert_eq!(manifest.bindings[0].id, BUILTIN_SECRETS);
        assert_eq!(manifest.bindings[0].operation, HTTP_REQUEST_OPERATION);
        assert_eq!(manifest.bindings[0].phase, PRE_CREDENTIALS_PHASE);
    }

    #[test]
    fn unsafe_header_mutation_is_rejected() {
        let err = validate_header_mutations(
            &BTreeMap::new(),
            &[("Authorization".into(), "Bearer nope".into())]
                .into_iter()
                .collect(),
        )
        .expect_err("unsafe header");
        assert!(err.to_string().contains("unsafe header"));
    }
}
