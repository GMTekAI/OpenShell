// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maximum-policy containment checks.
//!
//! This module answers a different question than the existing prover findings:
//! given a security-approved maximum policy and a candidate policy, does the
//! candidate allow any modeled action outside the maximum envelope?

use std::str::FromStr;

use crate::policy::{Endpoint, L7Rule, NetworkPolicyRule, PolicyModel};
use z3::ast::{Bool, Int, Regexp, String as Z3String};
use z3::{Context, SatResult, Solver};

const READ_ONLY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
const READ_WRITE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"];
const ALL_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

/// Result of checking whether a candidate policy is inside a maximum policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaximumPolicyCheck {
    /// Every modeled candidate action is contained by the maximum policy.
    WithinMax,
    /// The candidate allows at least one modeled action outside the maximum.
    ExceedsMax {
        /// Concrete action allowed by the candidate but not by the maximum.
        counterexample: PolicyCounterexample,
    },
    /// The policy uses a surface the first containment slice does not model.
    Unsupported {
        /// Human-readable reason. The check must fail closed at callers.
        reason: String,
    },
}

/// A representative action that witnesses maximum-policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCounterexample {
    pub binary: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub reason: String,
}

struct SymbolicAction {
    binary: Z3String,
    host: Z3String,
    port: Int,
    protocol: Z3String,
    method: Z3String,
    path: Z3String,
}

/// Check whether `candidate` is semantically contained by `maximum` for the
/// currently modeled allow surface.
pub fn check_within_maximum(maximum: &PolicyModel, candidate: &PolicyModel) -> MaximumPolicyCheck {
    if let Some(reason) = unsupported_reason("maximum", maximum) {
        return MaximumPolicyCheck::Unsupported { reason };
    }
    if let Some(reason) = unsupported_reason("candidate", candidate) {
        return MaximumPolicyCheck::Unsupported { reason };
    }

    match find_z3_violation(maximum, candidate) {
        Z3EnvelopeResult::WithinMax => MaximumPolicyCheck::WithinMax,
        Z3EnvelopeResult::ExceedsMax { counterexample } => {
            MaximumPolicyCheck::ExceedsMax { counterexample }
        }
        Z3EnvelopeResult::Unsupported { reason } => MaximumPolicyCheck::Unsupported { reason },
    }
}

enum Z3EnvelopeResult {
    WithinMax,
    ExceedsMax {
        counterexample: PolicyCounterexample,
    },
    Unsupported {
        reason: String,
    },
}

fn find_z3_violation(maximum: &PolicyModel, candidate: &PolicyModel) -> Z3EnvelopeResult {
    let _ctx = Context::thread_local();
    let solver = Solver::new();
    let action = SymbolicAction {
        binary: Z3String::new_const("action_binary"),
        host: Z3String::new_const("action_host"),
        port: Int::new_const("action_port"),
        protocol: Z3String::new_const("action_protocol"),
        method: Z3String::new_const("action_method"),
        path: Z3String::new_const("action_path"),
    };

    solver.assert(action.binary.regex_matches(&glob_regex("/**", "/")));
    solver.assert(action.host.regex_matches(&Regexp::full()));
    solver.assert(Int::from_u64(1).le(&action.port));
    solver.assert(action.port.le(65535));
    solver.assert(str_eq_any(&action.protocol, &["rest"]));
    solver.assert(str_eq_any(&action.method, ALL_METHODS));
    solver.assert(
        Z3String::from_str("/")
            .expect("literal")
            .prefix(&action.path),
    );

    let candidate_allows = policy_allows(candidate, &action);
    let maximum_allows = policy_allows(maximum, &action);
    let violation = Bool::and(&[candidate_allows, !maximum_allows]);
    solver.assert(&violation);

    match solver.check() {
        SatResult::Unsat => Z3EnvelopeResult::WithinMax,
        SatResult::Unknown => Z3EnvelopeResult::Unsupported {
            reason: "Z3 returned unknown while checking maximum-policy containment".to_owned(),
        },
        SatResult::Sat => {
            let Some(model) = solver.get_model() else {
                return Z3EnvelopeResult::Unsupported {
                    reason: "Z3 returned sat without a model for maximum-policy containment"
                        .to_owned(),
                };
            };
            let Some(counterexample) = counterexample_from_model(&model, &action) else {
                return Z3EnvelopeResult::Unsupported {
                    reason: "Z3 returned sat but the model could not be decoded into a maximum-policy counterexample".to_owned(),
                };
            };
            Z3EnvelopeResult::ExceedsMax { counterexample }
        }
    }
}

fn policy_allows(policy: &PolicyModel, action: &SymbolicAction) -> Bool {
    bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_allows(rule, action)),
    )
}

fn rule_allows(rule: &NetworkPolicyRule, action: &SymbolicAction) -> Bool {
    Bool::and(&[
        bool_or(
            rule.binaries
                .iter()
                .map(|binary| action.binary.regex_matches(&glob_regex(&binary.path, "/"))),
        ),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_allows(endpoint, action)),
        ),
    ])
}

fn endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    let mut constraints = vec![
        bool_or(
            endpoint
                .effective_ports()
                .into_iter()
                .map(|port| action.port.eq(Int::from_u64(u64::from(port)))),
        ),
        action
            .host
            .regex_matches(&glob_regex(&endpoint.host.to_ascii_lowercase(), ".")),
    ];

    if !normalized_protocol(&endpoint.protocol).is_empty() {
        constraints.push(action.protocol.eq(normalized_protocol(&endpoint.protocol)));
        constraints.push(bool_or(effective_rest_allows(endpoint).into_iter().map(
            |(method, path)| {
                Bool::and(&[
                    action.method.eq(method.as_str()),
                    action.path.regex_matches(&glob_regex(&path, "/")),
                ])
            },
        )));
    }

    Bool::and(&constraints)
}

fn counterexample_from_model(
    model: &z3::Model,
    action: &SymbolicAction,
) -> Option<PolicyCounterexample> {
    let port = model.eval(&action.port, true)?.as_u64()?;
    Some(PolicyCounterexample {
        binary: model.eval(&action.binary, true)?.as_string()?,
        host: model.eval(&action.host, true)?.as_string()?,
        port: u16::try_from(port).ok()?,
        protocol: model.eval(&action.protocol, true)?.as_string()?,
        method: model.eval(&action.method, true)?.as_string()?,
        path: model.eval(&action.path, true)?.as_string()?,
        reason: "candidate allows an action outside the maximum policy".to_owned(),
    })
}

fn bool_or(values: impl IntoIterator<Item = Bool>) -> Bool {
    let values: Vec<Bool> = values.into_iter().collect();
    if values.is_empty() {
        Bool::from_bool(false)
    } else {
        Bool::or(&values)
    }
}

fn str_eq_any(value: &Z3String, options: &[&str]) -> Bool {
    bool_or(options.iter().map(|option| value.eq(*option)))
}

fn glob_regex(pattern: &str, separator: &str) -> Regexp {
    if pattern == "**" {
        return Regexp::full();
    }

    let mut parts = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '*' && chars.peek() == Some(&'*') {
            chars.next();
            parts.push(Regexp::full());
        } else if ch == '*' {
            parts.push(non_separator_regex(separator).star());
        } else {
            parts.push(Regexp::literal(&ch.to_string()));
        }
    }

    if parts.is_empty() {
        Regexp::literal("")
    } else {
        let refs: Vec<&Regexp> = parts.iter().collect();
        Regexp::concat(&refs)
    }
}

fn non_separator_regex(separator: &str) -> Regexp {
    match separator {
        "/" => Regexp::union(&[&Regexp::range(&' ', &'.'), &Regexp::range(&'0', &'~')]),
        "." => Regexp::union(&[&Regexp::range(&' ', &'-'), &Regexp::range(&'/', &'~')]),
        _ => Regexp::full(),
    }
}

fn unsupported_reason(prefix: &str, policy: &PolicyModel) -> Option<String> {
    for (rule_name, rule) in &policy.network_policies {
        for endpoint in &rule.endpoints {
            if !endpoint.path.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses endpoint path scoping, which maximum containment does not model yet"
                ));
            }
            if unsupported_glob_pattern(&endpoint.host) {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses a host glob pattern outside the modeled subset"
                ));
            }
            if !endpoint.allowed_ips.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses allowed_ips/CIDR scoping, which maximum containment does not model yet"
                ));
            }
            if !endpoint.deny_rules.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses deny_rules, which maximum containment does not model yet"
                ));
            }
            if endpoint.effective_ports().is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' endpoint {} has no modeled port",
                    endpoint_label(endpoint)
                ));
            }
            if !endpoint.tls.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses tls '{}', which maximum containment does not model yet",
                    endpoint.tls
                ));
            }
            if endpoint.allow_encoded_slash
                || endpoint.websocket_credential_rewrite
                || endpoint.request_body_credential_rewrite
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses endpoint behavior flags that maximum containment does not model yet"
                ));
            }
            if !endpoint.persisted_queries.is_empty()
                || !endpoint.graphql_persisted_queries.is_empty()
                || endpoint.graphql_max_body_bytes != 0
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses GraphQL persisted-query controls, which maximum containment does not model yet"
                ));
            }
            if !endpoint.mcp_server.is_empty()
                || !endpoint.mcp_tool.is_empty()
                || !endpoint.mcp_resource.is_empty()
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses MCP controls, which maximum containment does not model yet"
                ));
            }
            if normalized_protocol(&endpoint.protocol) == "graphql" {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses GraphQL protocol controls, which maximum containment does not model yet"
                ));
            }
            let protocol = normalized_protocol(&endpoint.protocol);
            if !protocol.is_empty() && !protocol.eq_ignore_ascii_case("rest") {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses protocol '{}', which maximum containment does not model yet",
                    endpoint.protocol
                ));
            }
            if !protocol.is_empty() && endpoint.enforcement != "enforce" {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses L7 protocol '{}' without enforcement mode 'enforce'",
                    endpoint.protocol
                ));
            }
            for rule in &endpoint.rules {
                if l7_rule_is_unsupported(rule) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses L7 query, SQL, or GraphQL allow controls, which maximum containment does not model yet"
                    ));
                }
                if !rule.method.is_empty() && !modeled_rest_method(&rule.method) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses REST method '{}', which maximum containment does not model yet",
                        rule.method
                    ));
                }
                if unsupported_glob_pattern(&rule.path) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses a path glob pattern outside the modeled subset"
                    ));
                }
            }
        }
        for binary in &rule.binaries {
            if unsupported_glob_pattern(&binary.path) {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses a binary glob pattern outside the modeled subset"
                ));
            }
        }
    }
    None
}

fn l7_rule_is_unsupported(rule: &L7Rule) -> bool {
    !rule.command.is_empty()
        || !rule.query.is_empty()
        || !rule.operation_type.is_empty()
        || !rule.operation_name.is_empty()
        || !rule.fields.is_empty()
}

fn effective_rest_allows(endpoint: &Endpoint) -> Vec<(String, String)> {
    if normalized_protocol(&endpoint.protocol).is_empty() {
        return ALL_METHODS
            .iter()
            .map(|method| ((*method).to_owned(), "**".to_owned()))
            .collect();
    }

    match endpoint.access.as_str() {
        "read-only" => methods_with_path(READ_ONLY_METHODS, "**"),
        "read-write" => methods_with_path(READ_WRITE_METHODS, "**"),
        "full" => methods_with_path(ALL_METHODS, "**"),
        _ if endpoint.rules.is_empty() => Vec::new(),
        _ => {
            let mut allows = Vec::new();
            for rule in &endpoint.rules {
                if rule.method.is_empty() {
                    continue;
                }
                let path = if rule.path.is_empty() {
                    "**".to_owned()
                } else {
                    rule.path.clone()
                };
                if rule.method == "*" {
                    allows.extend(methods_with_path(ALL_METHODS, &path));
                } else if rule.method.eq_ignore_ascii_case("GET") {
                    allows.extend(methods_with_path(&["GET", "HEAD"], &path));
                } else {
                    allows.push((rule.method.to_ascii_uppercase(), path));
                }
            }
            allows
        }
    }
}

fn methods_with_path(methods: &[&str], path: &str) -> Vec<(String, String)> {
    methods
        .iter()
        .map(|method| ((*method).to_owned(), path.to_owned()))
        .collect()
}

fn modeled_rest_method(method: &str) -> bool {
    method == "*" || ALL_METHODS.contains(&method.to_ascii_uppercase().as_str())
}

fn unsupported_glob_pattern(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|ch| matches!(ch, '?' | '[' | ']' | '{' | '}' | '\\'))
}

fn normalized_protocol(protocol: &str) -> &str {
    protocol.trim()
}

fn endpoint_label(endpoint: &Endpoint) -> String {
    if endpoint.host.is_empty() {
        "<hostless>".to_owned()
    } else {
        endpoint.host.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy_str;

    fn policy(endpoint: &str, binaries: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
{endpoint}
    binaries:
{binaries}
"
        ))
        .expect("parse policy")
    }

    fn one_rest_endpoint(extra: &str) -> String {
        format!(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
{extra}"
        )
    }

    fn gh_binary() -> &'static str {
        "      - path: /usr/bin/gh"
    }

    #[test]
    fn exact_rest_rule_is_within_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn broader_rest_path_exceeds_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected candidate to exceed maximum");
        };
        assert_eq!(counterexample.method, "GET");
        assert_eq!(counterexample.host, "api.github.com");
        assert!(counterexample.path.starts_with("/repos/NVIDIA/"));
        assert!(
            !counterexample
                .path
                .starts_with("/repos/NVIDIA/OpenShell/issues/")
        );
    }

    #[test]
    fn method_escalation_exceeds_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: POST
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected method escalation");
        };
        assert_eq!(counterexample.method, "POST");
    }

    #[test]
    fn head_is_contained_by_get_like_runtime_method_matching() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: HEAD
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn custom_rest_methods_are_unsupported_until_modeled() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: TRACE
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn host_wildcard_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r#"      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only"#,
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn binary_wildcard_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint("        access: read-only"),
            "      - path: /usr/bin/*",
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn port_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        ports: [443, 8443]
        protocol: rest
        enforcement: enforce
        access: read-only",
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected port broadening");
        };
        assert_eq!(counterexample.port, 8443);
    }

    #[test]
    fn l4_candidate_exceeds_l7_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn maximum_l4_covers_l7_candidate() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint("        access: read-write"),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn maximum_wildcards_cover_exact_candidate() {
        let maximum = policy(
            r#"      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**"#,
            "      - path: /usr/bin/*",
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn deny_rules_are_unsupported_until_modeled() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: POST
            path: /admin/**",
            gh_binary(),
        );
        let candidate = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let MaximumPolicyCheck::Unsupported { reason } = check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected unsupported deny rule");
        };
        assert!(reason.contains("deny_rules"));
    }

    #[test]
    fn query_graphql_cidr_and_mcp_surfaces_are_unsupported() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let query_candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /search/issues
              query:
                org: NVIDIA",
            ),
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &query_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let graphql_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [repository]",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &graphql_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let cidr_candidate = policy(
            r#"      - port: 443
        allowed_ips: ["10.0.5.0/24"]"#,
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &cidr_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let mcp_candidate = policy(
            r"      - host: github.mcp.local
        port: 443
        protocol: rest
        mcp_server: github
        mcp_tool: get_issue",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &mcp_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn non_enforcing_l7_modes_are_unsupported_until_modeled() {
        let enforced_maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let audit_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: audit
        access: read-only",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&enforced_maximum, &audit_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let tls_skip_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        tls: skip
        access: read-only",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&enforced_maximum, &tls_skip_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let websocket_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: websocket
        enforcement: enforce
        access: read-only",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&enforced_maximum, &websocket_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn endpoint_behavior_flags_are_unsupported_until_modeled() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
        allow_encoded_slash: true",
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn unsupported_glob_syntax_fails_closed() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/?",
            ),
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }
}
