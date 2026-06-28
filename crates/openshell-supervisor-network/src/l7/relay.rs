// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::{L7Provider, RelayOutcome};
use crate::l7::rest::WebSocketExtensionMode;
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::opa::{PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::activity::{ActivitySender, try_record_activity};
use openshell_core::secrets::{self, SecretResolver};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, SeverityId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

/// Context for L7 request policy evaluation.
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Actual connected upstream peer IP, used for request-selected endpoint
    /// pin validation after shared-origin route selection.
    pub(crate) upstream_ip: Option<std::net::IpAddr>,
    /// Scheme-derived default port for HTTP authority normalization: 443 for
    /// TLS-terminated CONNECT tunnels and 80 for plaintext/forward HTTP.
    pub(crate) http_default_port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    /// Anonymous activity counter channel.
    pub(crate) activity_tx: Option<ActivitySender>,
    /// Dynamic credentials (token grants) keyed by endpoint-bound provider metadata.
    pub(crate) dynamic_credentials: Option<
        Arc<
            std::sync::RwLock<
                std::collections::HashMap<String, openshell_core::proto::ProviderProfileCredential>,
            >,
        >,
    >,
    /// Dynamic token grant resolver for endpoint-bound credentials.
    pub(crate) token_grant_resolver:
        Option<Arc<dyn crate::l7::token_grant_injection::TokenGrantResolver>>,
}

pub(crate) fn scoped_secret_resolver(
    ctx: &L7EvalContext,
    authorized_credential_keys: &[String],
    exclusive: bool,
) -> Option<Arc<SecretResolver>> {
    let resolver = ctx.secret_resolver.as_ref()?;
    Some(Arc::new(resolver.scoped_to_credential_keys(
        authorized_credential_keys,
        exclusive,
    )))
}

fn scoped_eval_context(
    ctx: &L7EvalContext,
    authorized_credential_keys: &[String],
    exclusive: bool,
) -> L7EvalContext {
    L7EvalContext {
        host: ctx.host.clone(),
        port: ctx.port,
        upstream_ip: ctx.upstream_ip,
        http_default_port: ctx.http_default_port,
        policy_name: ctx.policy_name.clone(),
        binary_path: ctx.binary_path.clone(),
        ancestors: ctx.ancestors.clone(),
        cmdline_paths: ctx.cmdline_paths.clone(),
        secret_resolver: scoped_secret_resolver(ctx, authorized_credential_keys, exclusive),
        activity_tx: ctx.activity_tx.clone(),
        dynamic_credentials: if exclusive {
            None
        } else {
            ctx.dynamic_credentials.clone()
        },
        token_grant_resolver: if exclusive {
            None
        } else {
            ctx.token_grant_resolver.clone()
        },
    }
}

#[derive(Default)]
pub(crate) struct UpgradeRelayOptions<'a> {
    pub(crate) websocket_request: bool,
    pub(crate) websocket: WebSocketUpgradeBehavior,
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    pub(crate) engine: Option<&'a TunnelPolicyEngine>,
    pub(crate) ctx: Option<&'a L7EvalContext>,
    pub(crate) enforcement: EnforcementMode,
    pub(crate) target: String,
    pub(crate) query_params: std::collections::HashMap<String, Vec<String>>,
    pub(crate) policy_name: String,
}

#[derive(Default)]
pub(crate) struct WebSocketUpgradeBehavior {
    pub(crate) credential_rewrite: bool,
    pub(crate) message_policy: WebSocketMessagePolicy,
    pub(crate) permessage_deflate: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum WebSocketMessagePolicy {
    #[default]
    None,
    Transport,
    Graphql,
}

impl WebSocketMessagePolicy {
    fn inspects_messages(self) -> bool {
        self != Self::None
    }

    fn is_graphql(self) -> bool {
        self == Self::Graphql
    }
}

#[derive(Debug, Clone, Copy)]
enum ParseRejectionMode {
    L7Endpoint,
    Passthrough,
}

fn parse_rejection_detail(error: &str, mode: ParseRejectionMode) -> String {
    if error.contains("encoded '/' (%2F)") {
        match mode {
            ParseRejectionMode::L7Endpoint => format!(
                "{error}; set allow_encoded_slash: true on this endpoint if the upstream requires encoded slashes"
            ),
            ParseRejectionMode::Passthrough => format!(
                "{error}; passthrough credential relay uses strict path parsing, so configure this endpoint with protocol: rest and allow_encoded_slash: true for encoded-slash APIs, or use tls: skip if HTTP parsing is not needed"
            ),
        }
    } else {
        error.to_string()
    }
}

fn emit_parse_rejection(ctx: &L7EvalContext, detail: &str, engine_type: &str) {
    let policy_name = if ctx.policy_name.is_empty() {
        "-"
    } else {
        &ctx.policy_name
    };
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(policy_name, engine_type)
        .message(format!(
            "HTTP request rejected before policy evaluation for {}:{}",
            ctx.host, ctx.port
        ))
        .status_detail(detail)
        .build();
    ocsf_emit!(event);
    emit_activity(ctx, true, "l7_parse_rejection");
}

fn engine_type_for_protocol(protocol: L7Protocol) -> &'static str {
    match protocol {
        L7Protocol::Graphql => "l7-graphql",
        L7Protocol::JsonRpc => "l7-jsonrpc",
        L7Protocol::Mcp => "l7-mcp",
        L7Protocol::Websocket => "l7-websocket",
        L7Protocol::Rest | L7Protocol::Sql => "l7",
    }
}

async fn deny_h2c_upgrade_if_requested<C>(
    req: &crate::l7::provider::L7Request,
    config: &L7EndpointConfig,
    ctx: &L7EvalContext,
    client: &mut C,
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    if !crate::l7::rest::request_is_h2c_upgrade(&req.raw_header) {
        return Ok(false);
    }

    emit_parse_rejection(
        ctx,
        crate::l7::rest::UNSUPPORTED_H2C_UPGRADE_DETAIL,
        engine_type_for_protocol(config.protocol),
    );
    crate::l7::rest::RestProvider::default()
        .deny(
            req,
            &ctx.policy_name,
            crate::l7::rest::UNSUPPORTED_H2C_UPGRADE_DETAIL,
            client,
        )
        .await?;
    Ok(true)
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest | L7Protocol::Websocket => {
            relay_rest(config, &engine, client, upstream, ctx).await
        }
        L7Protocol::Graphql => relay_graphql(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            if close_if_stale(engine.generation_guard(), ctx) {
                return Ok(());
            }
            // SQL provider is Phase 3 — fall through to passthrough with warning
            {
                let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Other)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message("SQL L7 provider not yet implemented, falling back to passthrough")
                    .build();
                ocsf_emit!(event);
            }
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
        L7Protocol::JsonRpc | L7Protocol::Mcp => {
            relay_jsonrpc(config, &engine, client, upstream, ctx).await
        }
    }
}

/// Run HTTP L7 inspection with per-request protocol selection.
///
/// This is used when multiple L7 endpoints share a host:port, for example a
/// REST API under `/repos/**` and a GraphQL API under `/graphql`.
pub async fn relay_with_route_selection<C, U>(
    configs: &[L7EndpointConfig],
    engine: TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let canonicalize_options = crate::l7::path::CanonicalizeOptions {
        allow_encoded_slash: configs.iter().any(|config| config.allow_encoded_slash),
        ..Default::default()
    };
    let provider = if credential_rewrite_possible(None, ctx)
        || configs
            .iter()
            .any(|config| credential_rewrite_possible(Some(config), ctx))
    {
        crate::l7::rest::RestProvider::with_credential_boundary(canonicalize_options)
    } else {
        crate::l7::rest::RestProvider::with_options(canonicalize_options)
    };

    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let mut req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 route-selected connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7");
                }
                return Ok(());
            }
        };

        let Some(config) = select_l7_config_for_path(configs, &req.target) else {
            crate::l7::rest::RestProvider::default()
                .deny(
                    &req,
                    &ctx.policy_name,
                    "no L7 endpoint path matched request",
                    client,
                )
                .await?;
            return Ok(());
        };
        if enforce_selected_endpoint_canonicalization(config, &req, client, ctx).await? {
            return Ok(());
        }
        if enforce_credential_ip_boundary(configs, &req, client, ctx).await? {
            return Ok(());
        }
        if enforce_http_credential_boundary(Some(config), &req, client, ctx).await? {
            return Ok(());
        }

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        let graphql_info = if config.protocol == L7Protocol::Graphql {
            match crate::l7::graphql::inspect_graphql_request(
                client,
                &mut req,
                config.graphql_max_body_bytes,
            )
            .await
            {
                Ok(info) => Some(info),
                Err(e) => {
                    if is_benign_connection_error(&e) {
                        debug!(
                            host = %ctx.host,
                            port = ctx.port,
                            error = %e,
                            "GraphQL L7 connection closed"
                        );
                    } else {
                        let detail =
                            parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                        emit_parse_rejection(ctx, &detail, "l7-graphql");
                    }
                    return Ok(());
                }
            }
        } else {
            None
        };
        let jsonrpc_info = if config.protocol.is_jsonrpc_family() {
            if crate::l7::jsonrpc::jsonrpc_receive_stream_request(&req) {
                Some(crate::l7::jsonrpc::JsonRpcRequestInfo::receive_stream())
            } else if config.protocol == L7Protocol::Mcp
                && req.action.eq_ignore_ascii_case("DELETE")
            {
                Some(crate::l7::jsonrpc::JsonRpcRequestInfo::session_termination(
                    &req,
                ))
            } else {
                match crate::l7::http::read_body_for_inspection(
                    client,
                    &mut req,
                    config.json_rpc_max_body_bytes,
                )
                .await
                {
                    Ok(body) => Some(crate::l7::jsonrpc::parse_jsonrpc_body_with_options(
                        &body,
                        crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(config),
                    )),
                    Err(e) => {
                        if is_benign_connection_error(&e) {
                            debug!(
                                host = %ctx.host,
                                port = ctx.port,
                                error = %e,
                                "JSON-RPC L7 connection closed"
                            );
                        } else {
                            let detail = parse_rejection_detail(
                                &e.to_string(),
                                ParseRejectionMode::L7Endpoint,
                            );
                            emit_parse_rejection(ctx, &detail, "l7-jsonrpc");
                        }
                        return Ok(());
                    }
                }
            }
        } else {
            None
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let target_resolver = scoped_secret_resolver(
            ctx,
            &[],
            configs.iter().any(|candidate| {
                candidate.matches_path(&req.target) && !candidate.credential_keys.is_empty()
            }),
        );
        let (eval_target, redacted_target) = if let Some(ref resolver) = target_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: graphql_info.clone(),
            jsonrpc: jsonrpc_info.clone(),
        };
        let websocket_request = crate::l7::rest::request_is_websocket_upgrade(&req.raw_header);
        if config.protocol == L7Protocol::Websocket && !websocket_request {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    "websocket endpoint requires a valid WebSocket upgrade request",
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }

        let parse_error_reason = graphql_info
            .as_ref()
            .and_then(|info| info.error.as_deref())
            .map(|error| format!("GraphQL request rejected: {error}"))
            .or_else(|| {
                jsonrpc_info
                    .as_ref()
                    .and_then(|info| info.error.as_deref())
                    .map(|error| format!("JSON-RPC request rejected: {error}"))
            });
        let force_deny = parse_error_reason.is_some();
        let (allowed, reason) = if let Some(reason) = parse_error_reason {
            (false, reason)
        } else {
            evaluate_l7_request(&engine, ctx, &request_info)?
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };
        let engine_type = match config.protocol {
            L7Protocol::Graphql => "l7-graphql",
            L7Protocol::Websocket => "l7-websocket",
            L7Protocol::JsonRpc => "l7-jsonrpc",
            L7Protocol::Mcp => "l7-mcp",
            L7Protocol::Rest | L7Protocol::Sql => "l7",
        };
        let protocol_summary =
            l7_protocol_log_summary(graphql_info.as_ref(), jsonrpc_info.as_ref());
        emit_l7_request_log(
            ctx,
            &request_info,
            &redacted_target,
            decision_str,
            engine_type,
            &reason,
            &protocol_summary,
        );

        let _ = &eval_target;

        let mut credential_authorization = authorized_credential_keys(&engine, ctx, &request_info)?;
        if !allowed {
            credential_authorization.keys.clear();
        }
        let scoped_ctx = scoped_eval_context(
            ctx,
            &credential_authorization.keys,
            credential_authorization.exclusive,
        );
        let ctx = &scoped_ctx;

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
                &req,
                client,
                upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: ctx.secret_resolver.as_deref(),
                    generation_guard: Some(engine.generation_guard()),
                    websocket_extensions: websocket_extension_mode(config),
                    request_body_credential_rewrite: config.protocol == L7Protocol::Rest
                        && config.request_body_credential_rewrite,
                    credential_bearer_only: credential_authorization.exclusive,
                    credential_signing: config.credential_signing,
                    signing_service: &config.signing_service,
                    signing_region: &config.signing_region,
                    host: &ctx.host,
                    port: ctx.port,
                    http_default_port: ctx.http_default_port,
                },
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => return Ok(()),
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let mut options = upgrade_options(
                        config,
                        ctx,
                        websocket_request,
                        &redacted_target,
                        &req.query_params,
                        Some(&engine),
                    );
                    options.websocket.permessage_deflate = websocket_permessage_deflate;
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }
    }
}

fn select_l7_config_for_path<'a>(
    configs: &'a [L7EndpointConfig],
    path: &str,
) -> Option<&'a L7EndpointConfig> {
    configs
        .iter()
        .filter(|config| config.matches_path(path))
        .max_by_key(|config| {
            (
                config.path_specificity(),
                usize::from(config.protocol == L7Protocol::Mcp),
            )
        })
}

fn emit_l7_request_log(
    ctx: &L7EvalContext,
    request_info: &L7RequestInfo,
    redacted_target: &str,
    decision_str: &str,
    engine_type: &str,
    reason: &str,
    protocol_summary: &str,
) {
    let (action_id, disposition_id, severity) = match decision_str {
        "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
        "allow" | "audit" => (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Informational,
        ),
        _ => (
            ActionId::Other,
            DispositionId::Other,
            SeverityId::Informational,
        ),
    };
    let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(severity)
        .http_request(HttpRequest::new(
            &request_info.action,
            OcsfUrl::new("http", &ctx.host, redacted_target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, engine_type)
        .message(format!(
            "L7_REQUEST {decision_str} {} {}:{}{}{} reason={}",
            request_info.action, ctx.host, ctx.port, redacted_target, protocol_summary, reason,
        ))
        .build();
    ocsf_emit!(event);
    emit_activity(ctx, decision_str == "deny", "l7_policy");
}

fn l7_protocol_log_summary(
    graphql_info: Option<&crate::l7::graphql::GraphqlRequestInfo>,
    jsonrpc_info: Option<&crate::l7::jsonrpc::JsonRpcRequestInfo>,
) -> String {
    if let Some(info) = graphql_info {
        return format!(" {}", graphql_log_summary(info));
    }

    if let Some(info) = jsonrpc_info {
        return format!(" rule_methods={}", rule_method_names_for_log(info));
    }

    String::new()
}

fn emit_activity(ctx: &L7EvalContext, denied: bool, deny_group: &'static str) {
    if let Some(tx) = &ctx.activity_tx {
        let _ = try_record_activity(tx, denied, deny_group);
    }
}

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// either switches to a parsed WebSocket relay for opted-in message policy /
/// credential rewriting or to raw bidirectional TCP copy for other upgrades.
pub(crate) async fn handle_upgrade<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
    options: UpgradeRelayOptions<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let use_websocket_relay = options.websocket_request
        && (options.websocket.message_policy.inspects_messages()
            || options.websocket.permessage_deflate
            || (options.websocket.credential_rewrite && options.secret_resolver.is_some()));
    let relay_mode = if use_websocket_relay {
        "websocket parsed relay"
    } else {
        "raw bidirectional relay (L7 enforcement no longer active)"
    };
    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .activity_name("Upgrade")
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .message(format!(
                "101 Switching Protocols — {relay_mode} [host:{host} port:{port} overflow_bytes:{}]",
                overflow.len()
            ))
            .build()
    );
    if use_websocket_relay {
        let resolver = if options.websocket.credential_rewrite {
            options.secret_resolver.as_deref()
        } else {
            None
        };
        let inspector = if options.websocket.message_policy.inspects_messages() {
            match (options.engine, options.ctx) {
                (Some(engine), Some(ctx)) => Some(crate::l7::websocket::InspectionOptions {
                    engine,
                    ctx,
                    enforcement: options.enforcement,
                    target: options.target.clone(),
                    query_params: options.query_params.clone(),
                    graphql_policy: options.websocket.message_policy.is_graphql(),
                }),
                _ => {
                    return Err(miette!(
                        "websocket message inspection missing policy context"
                    ));
                }
            }
        } else {
            None
        };
        let compression = if options.websocket.permessage_deflate {
            crate::l7::websocket::WebSocketCompression::PermessageDeflate
        } else {
            crate::l7::websocket::WebSocketCompression::None
        };
        return crate::l7::websocket::relay_with_options(
            client,
            upstream,
            overflow,
            host,
            port,
            crate::l7::websocket::RelayOptions {
                policy_name: &options.policy_name,
                resolver,
                inspector,
                compression,
            },
        )
        .await;
    }
    if !overflow.is_empty() {
        client.write_all(&overflow).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}

pub(crate) fn upgrade_options<'a>(
    config: &L7EndpointConfig,
    ctx: &'a L7EvalContext,
    websocket_request: bool,
    target: &str,
    query_params: &std::collections::HashMap<String, Vec<String>>,
    engine: Option<&'a TunnelPolicyEngine>,
) -> UpgradeRelayOptions<'a> {
    let websocket_credential_rewrite =
        matches!(config.protocol, L7Protocol::Rest | L7Protocol::Websocket)
            && config.websocket_credential_rewrite;
    let websocket_message_policy = if config.protocol == L7Protocol::Websocket {
        if config.websocket_graphql_policy {
            WebSocketMessagePolicy::Graphql
        } else {
            WebSocketMessagePolicy::Transport
        }
    } else {
        WebSocketMessagePolicy::None
    };
    UpgradeRelayOptions {
        websocket_request,
        websocket: WebSocketUpgradeBehavior {
            credential_rewrite: websocket_credential_rewrite,
            message_policy: websocket_message_policy,
            permessage_deflate: false,
        },
        secret_resolver: if websocket_credential_rewrite {
            ctx.secret_resolver.clone()
        } else {
            None
        },
        engine,
        ctx: engine.map(|_| ctx),
        enforcement: config.enforcement,
        target: target.to_string(),
        query_params: query_params.clone(),
        policy_name: ctx.policy_name.clone(),
    }
}

pub(crate) fn websocket_extension_mode(config: &L7EndpointConfig) -> WebSocketExtensionMode {
    if config.protocol == L7Protocol::Websocket
        || (config.protocol == L7Protocol::Rest && config.websocket_credential_rewrite)
    {
        WebSocketExtensionMode::PermessageDeflate
    } else {
        WebSocketExtensionMode::Preserve
    }
}

fn jsonrpc_engine_type(protocol: L7Protocol) -> &'static str {
    match protocol {
        L7Protocol::Mcp => "l7-mcp",
        _ => "l7-jsonrpc",
    }
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Build a provider carrying the per-endpoint canonicalization options so
    // request parsing honors the endpoint's `allow_encoded_slash` setting
    // (e.g. APIs like GitLab that embed `%2F` in path segments).
    let canonicalize_options = crate::l7::path::CanonicalizeOptions {
        allow_encoded_slash: config.allow_encoded_slash,
        ..Default::default()
    };
    let provider = if credential_rewrite_possible(Some(config), ctx) {
        crate::l7::rest::RestProvider::with_credential_boundary(canonicalize_options)
    } else {
        crate::l7::rest::RestProvider::with_options(canonicalize_options)
    };
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Parse one HTTP request from client
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7");
                }
                return Ok(()); // Close connection on parse error
            }
        };

        if enforce_http_credential_boundary(Some(config), &req, client, ctx).await? {
            return Ok(());
        }

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Rewrite credential placeholders in the request target BEFORE OPA
        // evaluation. OPA sees the redacted path; the resolved path goes only
        // to the upstream write.
        let target_resolver = scoped_secret_resolver(ctx, &[], !config.credential_keys.is_empty());
        let (eval_target, redacted_target) = if let Some(ref resolver) = target_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: None,
            jsonrpc: None,
        };
        let websocket_request = crate::l7::rest::request_is_websocket_upgrade(&req.raw_header);
        if config.protocol == L7Protocol::Websocket && !websocket_request {
            provider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    "websocket endpoint requires a valid WebSocket upgrade request",
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }

        // Evaluate L7 policy via Rego (using redacted target)
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Check if this is an upgrade request for logging purposes.
        let header_end = req
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(req.raw_header.len(), |p| p + 4);
        let is_upgrade_request = {
            let h = String::from_utf8_lossy(&req.raw_header[..header_end]);
            h.lines()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("upgrade:"))
        };

        let decision_str = match (allowed, config.enforcement, is_upgrade_request) {
            (true, _, true) => "allow_upgrade",
            (true, _, false) => "allow",
            (false, EnforcementMode::Audit, _) => "audit",
            (false, EnforcementMode::Enforce, _) => "deny",
        };

        // Log every L7 decision as an OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "allow" | "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7")
                .message(format!(
                    "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Store the resolved target for the deny response redaction
        let _ = &eval_target;

        let mut credential_authorization = authorized_credential_keys(engine, ctx, &request_info)?;
        if !allowed {
            credential_authorization.keys.clear();
        }
        let scoped_ctx = scoped_eval_context(
            ctx,
            &credential_authorization.keys,
            credential_authorization.exclusive,
        );
        let ctx = &scoped_ctx;

        if allowed || config.enforcement == EnforcementMode::Audit {
            let req_with_auth =
                match crate::l7::token_grant_injection::inject_if_needed(req, ctx).await {
                    Ok(req) => req,
                    Err(e) => {
                        warn!(
                            host = %ctx.host,
                            port = ctx.port,
                            error = %e,
                            "Token grant failed in L7 relay"
                        );
                        write_bad_gateway_response(client).await?;
                        return Ok(());
                    }
                };

            // Forward request to upstream and relay response
            let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
                &req_with_auth,
                client,
                upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: ctx.secret_resolver.as_deref(),
                    generation_guard: Some(engine.generation_guard()),
                    websocket_extensions: websocket_extension_mode(config),
                    request_body_credential_rewrite: config.protocol == L7Protocol::Rest
                        && config.request_body_credential_rewrite,
                    credential_bearer_only: credential_authorization.exclusive,
                    credential_signing: config.credential_signing,
                    signing_service: &config.signing_service,
                    signing_region: &config.signing_region,
                    host: &ctx.host,
                    port: ctx.port,
                    http_default_port: ctx.http_default_port,
                },
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {} // continue loop
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let mut options = upgrade_options(
                        config,
                        ctx,
                        websocket_request,
                        &redacted_target,
                        &req_with_auth.query_params,
                        Some(engine),
                    );
                    options.websocket.permessage_deflate = websocket_permessage_deflate;
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection (use redacted target)
            provider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }
    }
}

fn close_if_stale(guard: &PolicyGenerationGuard, ctx: &L7EvalContext) -> bool {
    if !guard.is_stale() {
        return false;
    }

    ocsf_emit!(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message(format!(
                "L7 tunnel closed after policy reload [host:{} port:{} captured_generation:{} current_generation:{}]",
                ctx.host,
                ctx.port,
                guard.captured_generation(),
                guard.current_generation(),
            ))
            .build()
    );
    true
}

fn credential_rewrite_possible(config: Option<&L7EndpointConfig>, ctx: &L7EvalContext) -> bool {
    ctx.secret_resolver.is_some()
        || ctx.dynamic_credentials.is_some()
        || config.is_some_and(|config| {
            !config.credential_keys.is_empty()
                || config.request_body_credential_rewrite
                || config.websocket_credential_rewrite
                || config.credential_signing.is_sigv4()
        })
}

async fn enforce_http_credential_boundary<C>(
    config: Option<&L7EndpointConfig>,
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let original_target = if req.raw_target.is_empty() {
        req.target.as_str()
    } else {
        req.raw_target.as_str()
    };
    let violation = if config.is_some_and(|config| config.protocol == L7Protocol::Mcp)
        && crate::l7::http::has_query_delimiter(original_target)
    {
        Some("MCP endpoint request targets must not contain a query delimiter".to_string())
    } else if credential_rewrite_possible(config, ctx) {
        crate::l7::http::validate_origin_form_request_target(&req.raw_header)
            .and_then(|()| {
                crate::l7::http::validate_bound_host_header(
                    &req.raw_header,
                    &ctx.host,
                    ctx.port,
                    ctx.http_default_port,
                )
            })
            .err()
            .map(|error| format!("credential-bearing request rejected: {error}"))
    } else {
        None
    };

    let Some(reason) = violation else {
        return Ok(false);
    };
    let safe_target = req.target.split('?').next().unwrap_or("/");
    crate::l7::rest::RestProvider::default()
        .deny_with_redacted_target(
            req,
            &ctx.policy_name,
            &reason,
            client,
            Some(safe_target),
            Some(crate::l7::rest::DenyResponseContext {
                host: Some(&ctx.host),
                port: Some(ctx.port),
                binary: Some(&ctx.binary_path),
            }),
        )
        .await?;
    emit_activity(ctx, true, "l7_parse_rejection");
    Ok(true)
}

async fn enforce_selected_endpoint_canonicalization<C>(
    config: &L7EndpointConfig,
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let raw_target = if req.raw_target.is_empty() {
        req.target.as_str()
    } else {
        req.raw_target.as_str()
    };
    let selected = crate::l7::path::canonicalize_request_target(
        raw_target,
        &crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: config.allow_encoded_slash,
            ..Default::default()
        },
    )
    .and_then(|(canonical, raw_query)| {
        let query_params = raw_query
            .as_deref()
            .map(crate::l7::rest::parse_query_params)
            .transpose()
            .map_err(|_| crate::l7::path::CanonicalizeError::MalformedTarget)?
            .unwrap_or_default();
        Ok((canonical.path, query_params))
    });

    let violation = match selected {
        Ok((path, query_params)) if path == req.target && query_params == req.query_params => None,
        Ok(_) => Some(
            "request-target canonicalization changed after selecting the endpoint policy"
                .to_string(),
        ),
        Err(error) => Some(format!(
            "request-target rejected by selected endpoint policy: {error}"
        )),
    };
    let Some(reason) = violation else {
        return Ok(false);
    };

    crate::l7::rest::RestProvider::default()
        .deny_with_redacted_target(
            req,
            &ctx.policy_name,
            &reason,
            client,
            Some(req.target.split('?').next().unwrap_or("/")),
            Some(crate::l7::rest::DenyResponseContext {
                host: Some(&ctx.host),
                port: Some(ctx.port),
                binary: Some(&ctx.binary_path),
            }),
        )
        .await?;
    emit_activity(ctx, true, "l7_parse_rejection");
    Ok(true)
}

async fn enforce_credential_ip_boundary<C>(
    configs: &[L7EndpointConfig],
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    ctx: &L7EvalContext,
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bound_configs: Vec<&L7EndpointConfig> = configs
        .iter()
        .filter(|config| !config.credential_keys.is_empty() && config.matches_path(&req.target))
        .collect();
    if bound_configs.is_empty() {
        return Ok(false);
    }
    let valid = ctx.upstream_ip.is_some_and(|ip| {
        bound_configs
            .iter()
            .all(|config| config.allows_upstream_ip(ip))
    });
    if valid {
        return Ok(false);
    }
    crate::l7::rest::RestProvider::default()
        .deny_with_redacted_target(
            req,
            &ctx.policy_name,
            "credential-bound MCP endpoint upstream IP is outside its allowed_ips pinset",
            client,
            Some(req.target.split('?').next().unwrap_or("/")),
            Some(crate::l7::rest::DenyResponseContext {
                host: Some(&ctx.host),
                port: Some(ctx.port),
                binary: Some(&ctx.binary_path),
            }),
        )
        .await?;
    emit_activity(ctx, true, "credential_ip_binding");
    Ok(true)
}

async fn relay_jsonrpc<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        // Future MCP version-profile request checks should hook here before OPA
        // evaluation. See McpOptions in proto/sandbox.proto for the policy
        // roadmap and source documentation.
        let parsed = match crate::l7::jsonrpc::parse_jsonrpc_http_request(
            client,
            config.json_rpc_max_body_bytes,
            crate::l7::path::CanonicalizeOptions {
                allow_encoded_slash: config.allow_encoded_slash,
                ..Default::default()
            },
            crate::l7::jsonrpc::JsonRpcInspectionOptions::for_config(config),
            credential_rewrite_possible(Some(config), ctx),
        )
        .await
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "JSON-RPC L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, jsonrpc_engine_type(config.protocol));
                }
                return Ok(());
            }
        };

        let req = parsed.request;
        let jsonrpc_info = parsed.info;

        if enforce_credential_ip_boundary(std::slice::from_ref(config), &req, client, ctx).await? {
            return Ok(());
        }

        if enforce_http_credential_boundary(Some(config), &req, client, ctx).await? {
            return Ok(());
        }

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let redacted_target = req.target.clone();

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: None,
            jsonrpc: Some(jsonrpc_info.clone()),
        };

        let parse_error_reason = jsonrpc_info
            .error
            .as_deref()
            .map(|e| format!("JSON-RPC request rejected: {e}"));
        let response_frame_reason =
            jsonrpc_response_frame_hard_deny_reason(config.protocol, &jsonrpc_info);
        let force_deny = parse_error_reason.is_some() || response_frame_reason.is_some();
        let (allowed, reason, jsonrpc_log_info) = if let Some(reason) = parse_error_reason {
            (false, reason, jsonrpc_info.clone())
        } else if let Some(reason) = response_frame_reason {
            (false, reason, jsonrpc_info.clone())
        } else {
            let evaluation =
                evaluate_jsonrpc_l7_request_for_log(engine, ctx, &request_info, &jsonrpc_info)?;
            (evaluation.allowed, evaluation.reason, evaluation.log_info)
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                _ => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
            };
            let endpoint = format!("{}:{}{}", ctx.host, ctx.port, redacted_target);
            let policy_version = engine.captured_generation();
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, jsonrpc_engine_type(config.protocol))
                .message(jsonrpc_log_message(
                    decision_str,
                    &request_info.action,
                    &endpoint,
                    &jsonrpc_log_info,
                    policy_version,
                    &reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let mut credential_authorization =
                authorized_credential_keys(engine, ctx, &request_info)?;
            if !allowed {
                credential_authorization.keys.clear();
            }
            let scoped_ctx = scoped_eval_context(
                ctx,
                &credential_authorization.keys,
                credential_authorization.exclusive,
            );
            let ctx = &scoped_ctx;
            // Future MCP response/SSE introspection or rewrite would hook here
            // before returning upstream bytes. The current policy schema has no
            // trusted-annotations or version-profile field, so MCP responses and
            // SSE streams are relayed unchanged; see McpOptions in
            // proto/sandbox.proto for planned policy extensions.
            let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
                &req,
                client,
                upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: ctx.secret_resolver.as_deref(),
                    generation_guard: Some(engine.generation_guard()),
                    credential_bearer_only: credential_authorization.exclusive,
                    host: &ctx.host,
                    port: ctx.port,
                    http_default_port: ctx.http_default_port,
                    ..Default::default()
                },
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing JSON-RPC L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded { .. } => {
                    return Ok(());
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }
    }
}

async fn relay_graphql<C, U>(
    config: &L7EndpointConfig,
    engine: &TunnelPolicyEngine,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let parsed = match crate::l7::graphql::parse_graphql_http_request_with_origin_requirement(
            client,
            config.graphql_max_body_bytes,
            crate::l7::path::CanonicalizeOptions {
                allow_encoded_slash: config.allow_encoded_slash,
                ..Default::default()
            },
            credential_rewrite_possible(Some(config), ctx),
        )
        .await
        {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(()),
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "GraphQL L7 connection closed"
                    );
                } else {
                    let detail =
                        parse_rejection_detail(&e.to_string(), ParseRejectionMode::L7Endpoint);
                    emit_parse_rejection(ctx, &detail, "l7-graphql");
                }
                return Ok(());
            }
        };

        let req = parsed.request;
        let graphql_info = parsed.info;

        if enforce_http_credential_boundary(Some(config), &req, client, ctx).await? {
            return Ok(());
        }

        if deny_h2c_upgrade_if_requested(&req, config, ctx, client).await? {
            return Ok(());
        }

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let target_resolver = scoped_secret_resolver(ctx, &[], !config.credential_keys.is_empty());
        let (eval_target, redacted_target) = if let Some(ref resolver) = target_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in GraphQL request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
            graphql: Some(graphql_info.clone()),
            jsonrpc: None,
        };

        // Malformed or ambiguous GraphQL requests, such as duplicated GET
        // control parameters, are rejected before policy evaluation. This
        // keeps parser-differential cases fail-closed even if the endpoint is
        // otherwise in audit mode.
        let parse_error_reason = graphql_info
            .error
            .as_deref()
            .map(|error| format!("GraphQL request rejected: {error}"));
        let force_deny = parse_error_reason.is_some();
        let (allowed, reason) = if let Some(reason) = parse_error_reason {
            (false, reason)
        } else {
            evaluate_l7_request(engine, ctx, &request_info)?
        };

        if close_if_stale(engine.generation_guard(), ctx) {
            return Ok(());
        }

        let decision_str = match (allowed, config.enforcement) {
            (_, _) if force_deny => "deny",
            (true, _) => "allow",
            (false, EnforcementMode::Audit) => "audit",
            (false, EnforcementMode::Enforce) => "deny",
        };

        {
            let (action_id, disposition_id, severity) = match decision_str {
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "allow" | "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let gql_summary = graphql_log_summary(&graphql_info);
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7-graphql")
                .message(format!(
                    "GRAPHQL_L7_REQUEST {decision_str} {} {}:{}{} {gql_summary} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        let _ = &eval_target;

        let mut credential_authorization = authorized_credential_keys(engine, ctx, &request_info)?;
        if !allowed {
            credential_authorization.keys.clear();
        }
        let scoped_ctx = scoped_eval_context(
            ctx,
            &credential_authorization.keys,
            credential_authorization.exclusive,
        );
        let ctx = &scoped_ctx;

        if allowed || (config.enforcement == EnforcementMode::Audit && !force_deny) {
            let outcome = crate::l7::rest::relay_http_request_with_resolver_guarded(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
                Some(engine.generation_guard()),
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {}
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing GraphQL L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded {
                    overflow,
                    websocket_permessage_deflate,
                } => {
                    let options = UpgradeRelayOptions {
                        websocket: WebSocketUpgradeBehavior {
                            permessage_deflate: websocket_permessage_deflate,
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    return handle_upgrade(
                        client, upstream, overflow, &ctx.host, ctx.port, options,
                    )
                    .await;
                }
            }
        } else {
            crate::l7::rest::RestProvider::default()
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                    Some(crate::l7::rest::DenyResponseContext {
                        host: Some(&ctx.host),
                        port: Some(ctx.port),
                        binary: Some(&ctx.binary_path),
                    }),
                )
                .await?;
            return Ok(());
        }
    }
}

fn graphql_log_summary(info: &crate::l7::graphql::GraphqlRequestInfo) -> String {
    if let Some(error) = &info.error {
        return format!("graphql_error={error:?}");
    }
    let ops: Vec<String> = info
        .operations
        .iter()
        .map(|op| {
            let name = op.operation_name.as_deref().unwrap_or("-");
            let fields = if op.fields.is_empty() {
                "-".to_string()
            } else {
                op.fields.join(",")
            };
            let persisted = op
                .persisted_query_hash
                .as_deref()
                .or(op.persisted_query_id.as_deref())
                .unwrap_or("-");
            format!(
                "type={} name={} fields={} persisted={}",
                op.operation_type, name, fields, persisted
            )
        })
        .collect();
    format!("graphql_ops={}", ops.join(";"))
}

pub(crate) fn jsonrpc_log_message(
    decision: &str,
    http_method: &str,
    endpoint: &str,
    info: &crate::l7::jsonrpc::JsonRpcRequestInfo,
    policy_version: u64,
    reason: &str,
) -> String {
    let rule_methods = rule_method_names_for_log(info);
    format!(
        "JSONRPC_L7_REQUEST decision={decision} http_method={http_method} endpoint={endpoint} rule_methods={rule_methods} policy_version={policy_version} reason={reason}"
    )
}

pub(crate) fn rule_method_names_for_log(info: &crate::l7::jsonrpc::JsonRpcRequestInfo) -> String {
    if info.calls.is_empty() {
        return "-".to_string();
    }
    info.calls
        .iter()
        .map(|call| sanitize_log_token(&call.method))
        .collect::<Vec<_>>()
        .join(",")
}

fn sanitize_log_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

struct JsonRpcEvaluation {
    allowed: bool,
    reason: String,
    log_info: crate::l7::jsonrpc::JsonRpcRequestInfo,
}

pub(crate) const JSONRPC_RESPONSE_FRAME_DENY_REASON: &str =
    "JSON-RPC response frames are not permitted from client to server";

pub(crate) fn jsonrpc_response_frame_hard_deny_reason(
    protocol: L7Protocol,
    jsonrpc: &crate::l7::jsonrpc::JsonRpcRequestInfo,
) -> Option<String> {
    (protocol != L7Protocol::Mcp && jsonrpc.has_response)
        .then(|| JSONRPC_RESPONSE_FRAME_DENY_REASON.to_string())
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
pub fn evaluate_l7_request(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    if let Some(jsonrpc) = &request.jsonrpc
        && jsonrpc.is_batch
        && !jsonrpc.calls.is_empty()
    {
        if jsonrpc.has_response {
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
            if !allowed {
                return Ok((false, reason));
            }
        }
        for call in &jsonrpc.calls {
            let item_request = jsonrpc_request_for_call(request, call);
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, &item_request)?;
            if !allowed {
                return Ok((false, reason));
            }
        }
        return Ok((true, String::new()));
    }

    evaluate_l7_request_once(engine, ctx, request)
}

fn evaluate_jsonrpc_l7_request_for_log(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
    jsonrpc: &crate::l7::jsonrpc::JsonRpcRequestInfo,
) -> Result<JsonRpcEvaluation> {
    if jsonrpc.has_response {
        let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
        if !allowed || !jsonrpc.is_batch || jsonrpc.calls.is_empty() {
            return Ok(JsonRpcEvaluation {
                allowed,
                reason,
                log_info: jsonrpc.clone(),
            });
        }
    }

    if jsonrpc.is_batch && !jsonrpc.calls.is_empty() {
        let mut denied_calls = Vec::new();
        let mut first_denied_reason = None;
        for call in &jsonrpc.calls {
            let item_request = jsonrpc_request_for_call(request, call);
            let (allowed, reason) = evaluate_l7_request_once(engine, ctx, &item_request)?;
            if !allowed {
                if first_denied_reason.is_none() {
                    first_denied_reason = Some(reason);
                }
                denied_calls.push(call.clone());
            }
        }

        if denied_calls.is_empty() {
            return Ok(JsonRpcEvaluation {
                allowed: true,
                reason: String::new(),
                log_info: jsonrpc.clone(),
            });
        }

        return Ok(JsonRpcEvaluation {
            allowed: false,
            reason: first_denied_reason.unwrap_or_else(|| "request denied by policy".to_string()),
            log_info: crate::l7::jsonrpc::JsonRpcRequestInfo {
                calls: denied_calls,
                is_batch: true,
                receive_stream: false,
                session_termination: false,
                has_response: false,
                error: None,
            },
        });
    }

    let (allowed, reason) = evaluate_l7_request_once(engine, ctx, request)?;
    Ok(JsonRpcEvaluation {
        allowed,
        reason,
        log_info: jsonrpc.clone(),
    })
}

fn jsonrpc_request_for_call(
    request: &L7RequestInfo,
    call: &crate::l7::jsonrpc::JsonRpcCallInfo,
) -> L7RequestInfo {
    let mut item_request = request.clone();
    item_request.jsonrpc = Some(crate::l7::jsonrpc::JsonRpcRequestInfo {
        calls: vec![call.clone()],
        is_batch: false,
        receive_stream: false,
        session_termination: false,
        has_response: false,
        error: None,
    });
    item_request
}

fn l7_input_json(ctx: &L7EvalContext, request: &L7RequestInfo) -> serde_json::Value {
    serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
            "graphql": request.graphql.clone(),
            "jsonrpc": request.jsonrpc.as_ref().map(|j| {
                let call = if j.is_batch { None } else { j.calls.first() };
                serde_json::json!({
                    "method": call.map(|call| call.method.as_str()),
                    "params": call.map(|call| &call.params),
                    "tool": call.and_then(|call| call.tool.as_deref()),
                    "receive_stream": j.receive_stream,
                    "session_termination": j.session_termination,
                    "has_response": j.has_response,
                    "error": j.error,
                })
            }),
        }
    })
}

fn credential_authorization_once(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(std::collections::HashSet<String>, bool)> {
    if engine.is_stale() {
        return Err(miette!(
            "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{}]",
            engine.captured_generation(),
            engine.current_generation(),
        ));
    }
    let input_json = l7_input_json(ctx, request);
    let mut engine = engine
        .engine()
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;
    engine
        .set_input_json(&input_json.to_string())
        .map_err(|error| miette!("{error}"))?;
    let value = engine
        .eval_rule("data.openshell.sandbox._authorized_credential_keys".into())
        .map_err(|error| miette!("{error}"))?;
    let values = match value {
        regorus::Value::Undefined => Vec::new(),
        regorus::Value::Array(values) => values.to_vec(),
        _ => return Err(miette!("authorized credential keys must be an array")),
    };
    let keys = values
        .iter()
        .map(|value| match value {
            regorus::Value::String(key) => Ok(key.to_string()),
            _ => Err(miette!("authorized credential key must be a string")),
        })
        .collect::<Result<_>>()?;
    let exclusive = engine
        .eval_rule("data.openshell.sandbox._credential_bound_request".into())
        .map_err(|error| miette!("{error}"))?
        == regorus::Value::from(true);
    Ok((keys, exclusive))
}

pub(crate) struct CredentialAuthorization {
    pub(crate) keys: Vec<String>,
    pub(crate) exclusive: bool,
}

pub(crate) fn authorized_credential_keys(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<CredentialAuthorization> {
    let mut authorized: Option<std::collections::HashSet<String>> = None;
    let mut exclusive = false;
    let mut intersect = |keys: std::collections::HashSet<String>, bound: bool| {
        exclusive |= bound;
        if let Some(current) = authorized.as_mut() {
            current.retain(|key| keys.contains(key));
        } else {
            authorized = Some(keys);
        }
    };

    if let Some(jsonrpc) = &request.jsonrpc
        && jsonrpc.is_batch
        && !jsonrpc.calls.is_empty()
    {
        if jsonrpc.has_response {
            let (keys, bound) = credential_authorization_once(engine, ctx, request)?;
            intersect(keys, bound);
        }
        for call in &jsonrpc.calls {
            let item_request = jsonrpc_request_for_call(request, call);
            let (keys, bound) = credential_authorization_once(engine, ctx, &item_request)?;
            intersect(keys, bound);
        }
    } else {
        let (keys, bound) = credential_authorization_once(engine, ctx, request)?;
        intersect(keys, bound);
    }

    let mut keys: Vec<String> = authorized.unwrap_or_default().into_iter().collect();
    keys.sort();
    Ok(CredentialAuthorization { keys, exclusive })
}

fn evaluate_l7_request_once(
    engine: &TunnelPolicyEngine,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    if engine.is_stale() {
        return Err(miette!(
            "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{}]",
            engine.captured_generation(),
            engine.current_generation(),
        ));
    }

    let input_json = l7_input_json(ctx, request);

    let mut engine = engine
        .engine()
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Relay HTTP traffic with credential injection only (no L7 OPA evaluation).
///
/// Used when TLS is auto-terminated but no L7 policy (`protocol` + `access`/`rules`)
/// is configured. Parses HTTP requests minimally to rewrite credential
/// placeholders and log requests for observability, then forwards everything.
pub async fn relay_passthrough_with_credentials<C, U>(
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    generation_guard: &PolicyGenerationGuard,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let scoped_ctx = scoped_eval_context(ctx, &[], false);
    let ctx = &scoped_ctx;
    // Passthrough path: no L7 policy is enforced here, so use default
    // (strict) canonicalization options. Calls to GitLab-style APIs that
    // need `%2F` must be configured as L7 endpoints so the per-endpoint
    // `allow_encoded_slash` opt-in applies.
    let provider = if credential_rewrite_possible(None, ctx) {
        crate::l7::rest::RestProvider::with_credential_boundary(
            crate::l7::path::CanonicalizeOptions::default(),
        )
    } else {
        crate::l7::rest::RestProvider::default()
    };
    let mut request_count: u64 = 0;
    let resolver = ctx.secret_resolver.as_deref();

    loop {
        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

        // Read next request from client.
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                let detail =
                    parse_rejection_detail(&e.to_string(), ParseRejectionMode::Passthrough);
                emit_parse_rejection(ctx, &detail, "http-parser");
                return Ok(());
            }
        };

        if enforce_http_credential_boundary(None, &req, client, ctx).await? {
            return Ok(());
        }

        if close_if_stale(generation_guard, ctx) {
            return Ok(());
        }

        request_count += 1;

        // Resolve and redact the target for logging.
        let redacted_target = if let Some(ref res) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, res) {
                Ok(result) => result.redacted,
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            req.target.clone()
        };

        // Log for observability via OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        let has_creds = resolver.is_some();
        {
            let event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "HTTP_REQUEST {} {}:{}{} credentials_injected={has_creds} request_num={request_count}",
                    req.action, ctx.host, ctx.port, redacted_target,
                ))
                .build();
            ocsf_emit!(event);
        }

        let req_with_auth = match crate::l7::token_grant_injection::inject_if_needed(req, ctx).await
        {
            Ok(req) => req,
            Err(e) => {
                warn!(
                    host = %ctx.host,
                    port = ctx.port,
                    error = %e,
                    "Token grant failed in passthrough relay"
                );
                write_bad_gateway_response(client).await?;
                return Ok(());
            }
        };

        // Forward request with credential rewriting and relay the response.
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let outcome = crate::l7::rest::relay_http_request_with_options_guarded(
            &req_with_auth,
            client,
            upstream,
            crate::l7::rest::RelayRequestOptions {
                resolver,
                generation_guard: Some(generation_guard),
                host: &ctx.host,
                port: ctx.port,
                http_default_port: ctx.http_default_port,
                ..Default::default()
            },
        )
        .await?;

        match outcome {
            RelayOutcome::Reusable => {} // continue loop
            RelayOutcome::Consumed => break,
            RelayOutcome::Upgraded { overflow, .. } => {
                return handle_upgrade(
                    client,
                    upstream,
                    overflow,
                    &ctx.host,
                    ctx.port,
                    UpgradeRelayOptions::default(),
                )
                .await;
            }
        }
    }

    debug!(
        host = %ctx.host,
        port = ctx.port,
        total_requests = request_count,
        "Credential injection relay completed"
    );

    Ok(())
}

async fn write_bad_gateway_response<W>(client: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(response).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use std::path::PathBuf;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");

    fn rest_token_grant_relay_context(
        resolver_response: std::result::Result<&str, &str>,
    ) -> (
        L7EndpointConfig,
        TunnelPolicyEngine,
        L7EvalContext,
        crate::l7::token_grant_injection::test_support::TokenGrantTestFixture,
    ) {
        let data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/**"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let provider_key = "api.example.test\t8080\t/v1/**\tprovider:access_token";
        let fixture = match resolver_response {
            Ok(token) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::success(
                    provider_key,
                    token,
                )
            }
            Err(error) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::failure(
                    provider_key,
                    error,
                )
            }
        };
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            http_default_port: 80,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            upstream_ip: None,
        };

        (config, tunnel_engine, ctx, fixture)
    }

    fn passthrough_token_grant_relay_context(
        resolver_response: std::result::Result<&str, &str>,
    ) -> (
        PolicyGenerationGuard,
        L7EvalContext,
        crate::l7::token_grant_injection::test_support::TokenGrantTestFixture,
    ) {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let provider_key = "api.example.test\t8080\t/v1/**\tprovider:access_token";
        let fixture = match resolver_response {
            Ok(token) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::success(
                    provider_key,
                    token,
                )
            }
            Err(error) => {
                crate::l7::token_grant_injection::test_support::TokenGrantTestFixture::failure(
                    provider_key,
                    error,
                )
            }
        };
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            http_default_port: 80,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            upstream_ip: None,
        };

        (generation_guard, ctx, fixture)
    }

    fn jsonrpc_test_relay_context() -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = r"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: jsonrpc.example.test
        port: 8000
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "jsonrpc.example.test".into(),
            port: 8000,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "jsonrpc.example.test".into(),
            port: 8000,
            http_default_port: 80,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/python3".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        (config, tunnel_engine, ctx)
    }

    fn mcp_test_relay_context() -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext) {
        let data = r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "mcp.example.test".into(),
            port: 8000,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "mcp.example.test".into(),
            port: 8000,
            http_default_port: 80,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/python3".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        (config, tunnel_engine, ctx)
    }

    fn authenticated_mcp_test_relay_context()
    -> (L7EndpointConfig, TunnelPolicyEngine, L7EvalContext, String) {
        let data = r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        tls: require
        enforcement: enforce
        credential_keys: [MCP_TOKEN]
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "mcp.example.test".into(),
            port: 8000,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let state = openshell_core::provider_credentials::ProviderCredentialState::from_environment_with_scope(
            1,
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "mcp-real-secret".to_string(),
            )]),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            vec!["MCP_TOKEN".to_string()],
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "provider-A".to_string(),
            )]),
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "provider-A".to_string(),
            )]),
        );
        let placeholder = state
            .snapshot()
            .child_env
            .get("MCP_TOKEN")
            .expect("credential placeholder")
            .clone();
        let ctx = L7EvalContext {
            host: "mcp.example.test".into(),
            port: 8000,
            upstream_ip: Some("127.0.0.1".parse().unwrap()),
            http_default_port: 80,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/python3".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: state.resolver(),
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };
        (config, tunnel_engine, ctx, placeholder)
    }

    fn mixed_encoded_slash_route_context() -> (
        Vec<L7EndpointConfig>,
        TunnelPolicyEngine,
        L7EvalContext,
        String,
    ) {
        let data = r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: /mcp%2Ftenant
        protocol: mcp
        tls: require
        enforcement: enforce
        credential_keys: [MCP_TOKEN]
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/node }
  rest_api:
    name: rest_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: /rest/**
        protocol: rest
        enforcement: enforce
        allow_encoded_slash: true
        rules:
          - allow:
              method: GET
              path: /rest/**
    binaries:
      - { path: /usr/bin/node }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "gateway.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (values, generation) = engine
            .query_endpoint_configs_with_generation(&input)
            .unwrap();
        let configs = values
            .iter()
            .filter_map(crate::l7::parse_l7_config)
            .collect();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let state = openshell_core::provider_credentials::ProviderCredentialState::from_environment_with_scope(
            1,
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "mcp-real-secret".to_string(),
            )]),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            vec!["MCP_TOKEN".to_string()],
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "provider-A".to_string(),
            )]),
            std::collections::HashMap::from([(
                "MCP_TOKEN".to_string(),
                "provider-A".to_string(),
            )]),
        );
        let placeholder = state.snapshot().child_env["MCP_TOKEN"].clone();
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            upstream_ip: Some("192.0.2.10".parse().unwrap()),
            http_default_port: 443,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: state.resolver(),
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
        };
        (configs, tunnel_engine, ctx, placeholder)
    }

    fn authorization_header_count(headers: &str) -> usize {
        headers
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            })
            .count()
    }

    #[test]
    fn parse_rejection_detail_adds_l7_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::L7Endpoint,
        );

        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("upstream requires encoded slashes"));
    }

    #[test]
    fn parse_rejection_detail_adds_passthrough_hint_for_encoded_slash() {
        let detail = parse_rejection_detail(
            "HTTP request-target rejected: request-target contains an encoded '/' (%2F) which is not allowed on this endpoint",
            ParseRejectionMode::Passthrough,
        );

        assert!(detail.contains("protocol: rest"));
        assert!(detail.contains("allow_encoded_slash: true"));
        assert!(detail.contains("tls: skip"));
    }

    #[test]
    fn parse_rejection_detail_preserves_other_errors() {
        let error = "HTTP headers contain invalid UTF-8";

        assert_eq!(
            parse_rejection_detail(error, ParseRejectionMode::L7Endpoint),
            error
        );
    }

    #[tokio::test]
    async fn l7_rest_relay_injects_token_grant_authorization_header() {
        let (config, tunnel_engine, ctx, fixture) =
            rest_token_grant_relay_context(Ok("grant-token"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nAuthorization: Bearer stale-token\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);

        assert!(upstream_request.starts_with("GET /v1/projects HTTP/1.1\r\n"));
        assert!(upstream_request.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!upstream_request.contains("stale-token"));
        assert_eq!(authorization_header_count(&upstream_request), 1);

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn l7_rest_relay_token_grant_failure_does_not_forward_request() {
        let (config, tunnel_engine, ctx, fixture) =
            rest_token_grant_relay_context(Err("oauth unavailable"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("bad gateway response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("502 Bad Gateway"));

        let mut upstream_request = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("upstream should close without forwarded data")
        .unwrap();
        assert_eq!(n, 0, "unauthenticated request must not reach upstream");

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn passthrough_relay_injects_token_grant_authorization_header() {
        let (generation_guard, ctx, fixture) =
            passthrough_token_grant_relay_context(Ok("grant-token"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nAuthorization: Bearer stale-token\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut upstream_request = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("request should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request[..n]);

        assert!(upstream_request.starts_with("GET /v1/projects HTTP/1.1\r\n"));
        assert!(upstream_request.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!upstream_request.contains("stale-token"));
        assert_eq!(authorization_header_count(&upstream_request), 1);

        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("204 No Content"));
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[tokio::test]
    async fn passthrough_relay_token_grant_failure_returns_bad_gateway_without_forwarding() {
        let (generation_guard, ctx, fixture) =
            passthrough_token_grant_relay_context(Err("oauth unavailable"));
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
            )
            .await
        });

        app.write_all(
            b"GET /v1/projects HTTP/1.1\r\nHost: api.example.test:8080\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should finish")
            .unwrap()
            .unwrap();

        let mut client_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut client_response),
        )
        .await
        .expect("bad gateway response should reach client")
        .unwrap();
        assert!(String::from_utf8_lossy(&client_response[..n]).contains("502 Bad Gateway"));

        let mut upstream_request = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_request),
        )
        .await
        .expect("upstream should close without forwarded data")
        .unwrap();
        assert_eq!(n, 0, "unauthenticated request must not reach upstream");

        fixture.assert_one_request("api.example.test\t8080\t/v1/**\tprovider:access_token");
    }

    #[test]
    fn websocket_text_policy_requires_explicit_message_rule() {
        let data = r#"
network_policies:
  ws_api:
    name: ws_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "gateway.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let generation = engine
            .evaluate_network_action_with_generation(&input)
            .unwrap()
            .1;
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            http_default_port: 80,
            policy_name: "ws_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        let request = L7RequestInfo {
            action: "WEBSOCKET_TEXT".into(),
            target: "/ws".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: None,
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();

        assert!(!allowed);
        assert!(reason.contains("WEBSOCKET_TEXT /ws not permitted"));
    }

    #[test]
    fn jsonrpc_batch_evaluates_each_call() {
        let data = r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.list"
          - allow:
              method: "reports.search"
        deny_rules:
          - method: "reports.delete"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            http_default_port: 80,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/rpc".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"[
                    {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                    {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}}
                ]"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"result":{"ok":true}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);
        assert!(reason.contains("response frames"));

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc request");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.has_response);
        assert_eq!(
            rule_method_names_for_log(&evaluation.log_info),
            "reports.list"
        );

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);
        assert!(reason.contains("response frames"));

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc response");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.has_response);
        assert_eq!(rule_method_names_for_log(&evaluation.log_info), "-");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}},
                {"jsonrpc":"2.0","id":3,"method":"reports.delete","params":{"id":"purge_cache"}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, _) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed);

        let jsonrpc = request.jsonrpc.as_ref().expect("jsonrpc request");
        let evaluation =
            evaluate_jsonrpc_l7_request_for_log(&tunnel_engine, &ctx, &request, jsonrpc).unwrap();
        assert!(!evaluation.allowed);
        assert!(evaluation.log_info.is_batch);
        assert_eq!(
            rule_method_names_for_log(&evaluation.log_info),
            "reports.delete"
        );

        let message = jsonrpc_log_message(
            "deny",
            "POST",
            "api.example.test:443/rpc",
            &evaluation.log_info,
            42,
            &evaluation.reason,
        );
        assert!(message.contains("rule_methods=reports.delete"));
        assert!(message.contains("policy_version=42"));
        assert!(!message.contains("reports.list"));
        assert!(!message.contains("reports.search"));
        assert!(!message.contains("private_query_value"));
        assert!(!message.contains("purge_cache"));
    }

    #[test]
    fn jsonrpc_request_params_do_not_affect_method_policy() {
        let data = r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.search"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            http_default_port: 80,
            policy_name: "jsonrpc_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/rpc".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"delete_resource","filters":{"scope":"workspace/secret"}}}"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":["ignored",{"nested":true}]}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        ));
        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");
    }

    #[test]
    fn mcp_tool_deny_rule_blocks_tools_call() {
        let data = r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: api.example.test
        port: 443
        path: "/mcp"
        protocol: mcp
        enforcement: enforce
        mcp:
          max_body_bytes: 131072
        rules:
          - allow:
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
              tool: read_status
        deny_rules:
          - method: tools/call
            tool: delete_resource
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            http_default_port: 80,
            policy_name: "mcp_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };
        let mut request = L7RequestInfo {
            action: "POST".into(),
            target: "/mcp".into(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: Some(crate::l7::jsonrpc::parse_jsonrpc_body(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{}}}"#,
                crate::l7::jsonrpc::JsonRpcInspectionMode::Mcp,
            )),
        };

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(allowed, "{reason}");

        request.jsonrpc = Some(crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_resource","arguments":{"scope":"workspace/main"}}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::Mcp,
        ));
        let parsed = request.jsonrpc.as_ref().expect("parsed MCP request");
        assert!(
            parsed.error.is_none(),
            "MCP request should parse: {parsed:?}"
        );
        assert_eq!(
            parsed.calls.first().and_then(|call| call.tool.as_deref()),
            Some("delete_resource")
        );

        let (allowed, reason) = evaluate_l7_request(&tunnel_engine, &ctx, &request).unwrap();
        assert!(!allowed, "delete_resource must match the MCP deny rule");
        assert!(
            reason.contains("deny rule"),
            "deny reason should identify policy denial: {reason}"
        );
    }

    #[test]
    fn jsonrpc_log_records_method_names_not_params() {
        let info = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.archive","params":{"id":"delete_resource","filters":{"scope":"secret-scope"}}}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let message = jsonrpc_log_message(
            "deny",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &info,
            42,
            "request denied by policy",
        );

        assert!(message.contains("endpoint=jsonrpc.example.com:443/rpc"));
        assert!(message.contains("rule_methods=reports.archive"));
        assert!(message.contains("policy_version=42"));
        assert!(!message.contains("delete_resource"));
        assert!(!message.contains("secret-scope"));

        let batch = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"[
                {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                {"jsonrpc":"2.0","id":2,"method":"reports.archive","params":{"id":"delete_resource"}}
            ]"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let batch_message = jsonrpc_log_message(
            "allow",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &batch,
            43,
            "",
        );

        assert!(batch_message.starts_with("JSONRPC_L7_REQUEST "));
        assert!(batch_message.contains("rule_methods=reports.list,reports.archive"));
        assert!(batch_message.contains("policy_version=43"));
        assert!(!batch_message.contains("delete_resource"));

        let no_params = crate::l7::jsonrpc::parse_jsonrpc_body(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            crate::l7::jsonrpc::JsonRpcInspectionMode::JsonRpc,
        );
        let no_params_message = jsonrpc_log_message(
            "allow",
            "POST",
            "jsonrpc.example.com:443/rpc",
            &no_params,
            44,
            "",
        );
        assert!(no_params_message.contains("rule_methods=initialize"));
    }

    #[tokio::test]
    async fn route_selected_websocket_upgrade_rejects_invalid_accept_without_forwarding_101() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Rest,
            path: "/ws".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            credential_keys: Vec::new(),
            allowed_ips: Vec::new(),
            websocket_graphql_policy: false,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            http_default_port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("Upgrade: websocket\r\n"));
        assert!(forwarded.contains("Connection: Upgrade\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n",
            )
            .await
            .unwrap();

        let err = tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should fail closed on invalid accept")
            .unwrap()
            .expect_err("invalid accept must fail the route-selected relay");
        assert!(err.to_string().contains("Sec-WebSocket-Accept"));

        let mut response = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client side should close without 101")
            .unwrap();
        assert_eq!(n, 0, "invalid response must not forward 101 headers");
    }

    #[tokio::test]
    async fn route_selected_websocket_rewrites_text_credentials_after_upgrade() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
          - allow:
              method: WEBSOCKET_TEXT
              path: "/ws"
        websocket_credential_rewrite: true
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Websocket,
            path: "/ws".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            credential_keys: Vec::new(),
            allowed_ips: Vec::new(),
            websocket_graphql_policy: false,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())).collect(),
        );
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").expect("placeholder env");
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            http_default_port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("Upgrade: websocket\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client should receive upgrade response")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("101 Switching Protocols"));

        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);
        app.write_all(&masked_text_frame(payload.as_bytes()))
            .await
            .unwrap();

        let (masked, rewritten) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_text_frame(&mut upstream),
        )
        .await
        .expect("rewritten websocket text should reach upstream")
        .unwrap();
        assert!(masked, "client-to-server frame must remain masked");
        assert_eq!(rewritten, r#"{"op":2,"d":{"token":"real-token"}}"#);
        assert!(!rewritten.contains(placeholder));

        drop(app);
        drop(upstream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;
    }

    #[tokio::test]
    async fn route_selected_graphql_websocket_rewrites_connection_init_credentials_after_upgrade() {
        let data = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
        websocket_credential_rewrite: true
    binaries:
      - { path: /usr/bin/node }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let configs = vec![L7EndpointConfig {
            protocol: L7Protocol::Websocket,
            path: "/graphql".into(),
            tls: crate::l7::TlsMode::Auto,
            enforcement: EnforcementMode::Enforce,
            graphql_max_body_bytes: 0,
            json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
            mcp_strict_tool_names: true,
            allow_encoded_slash: false,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: false,
            credential_keys: Vec::new(),
            allowed_ips: Vec::new(),
            websocket_graphql_policy: true,
            credential_signing: crate::l7::CredentialSigning::None,
            signing_service: String::new(),
            signing_region: String::new(),
        }];
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("T".to_string(), "real-token".to_string())).collect(),
        );
        let placeholder = child_env.get("T").expect("placeholder env");
        let ctx = L7EvalContext {
            host: "gateway.example.test".into(),
            port: 443,
            http_default_port: 443,
            policy_name: "route_api".into(),
            binary_path: "/usr/bin/node".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: resolver.map(Arc::new),
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"GET /graphql HTTP/1.1\r\nHost: gateway.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("upgrade request should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.contains("GET /graphql HTTP/1.1"));
        assert!(forwarded.contains("Upgrade: websocket\r\n"));

        upstream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            )
            .await
            .unwrap();

        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("client should receive upgrade response")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("101 Switching Protocols"));

        let payload = format!(
            r#"{{"type":"connection_init","payload":{{"authorization":"{placeholder}"}}}}"#
        );
        app.write_all(&masked_text_frame(payload.as_bytes()))
            .await
            .unwrap();

        let (masked, rewritten) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_text_frame(&mut upstream),
        )
        .await
        .expect("rewritten GraphQL WebSocket control message should reach upstream")
        .unwrap();
        assert!(masked, "client-to-server frame must remain masked");
        assert_eq!(
            rewritten,
            r#"{"type":"connection_init","payload":{"authorization":"real-token"}}"#
        );
        assert!(!rewritten.contains(placeholder));

        drop(app);
        drop(upstream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;
    }

    fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [0x11, 0x22, 0x33, 0x44];
        assert!(
            payload.len() <= 125,
            "test helper only supports small frames"
        );
        let payload_len = u8::try_from(payload.len()).expect("small frame length");
        let mut frame = vec![0x81, 0x80 | payload_len];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(idx, byte)| byte ^ mask[idx % 4]),
        );
        frame
    }

    async fn read_text_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> std::io::Result<(bool, String)> {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await?;
        assert_eq!(header[0] & 0x0f, 0x1, "expected text frame");
        let masked = header[1] & 0x80 != 0;
        let payload_len = usize::from(header[1] & 0x7f);
        assert!(payload_len <= 125, "test helper only supports small frames");
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        if masked {
            for (idx, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[idx % 4];
            }
        }
        Ok((masked, String::from_utf8(payload).expect("text payload")))
    }

    #[tokio::test]
    async fn l7_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let initial_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let reloaded_data = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/write"
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, initial_data).unwrap();
        let input = NetworkInput {
            host: "api.example.test".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (endpoint_config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
        let tunnel_engine = engine.clone_engine_for_tunnel(generation).unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            http_default_port: 80,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(first_upstream.starts_with("POST /write HTTP/1.1"));

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, reloaded_data).unwrap();
        app.write_all(
            b"POST /write HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(n, 0, "stale request must not be forwarded upstream");
    }

    #[tokio::test]
    async fn passthrough_relay_closes_keep_alive_tunnel_after_policy_generation_change() {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 8080,
            http_default_port: 80,
            policy_name: "rest_api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            upstream_ip: None,
        };

        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_passthrough_with_credentials(
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
                &generation_guard,
            )
            .await
        });

        app.write_all(
            b"GET /first HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        let mut first_upstream = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut first_upstream),
        )
        .await
        .expect("first passthrough request should reach upstream")
        .unwrap();
        let first_upstream = String::from_utf8_lossy(&first_upstream[..n]);
        assert!(first_upstream.starts_with("GET /first HTTP/1.1"));

        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .unwrap();

        let mut first_response = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.read(&mut first_response),
        )
        .await
        .expect("first passthrough response should reach client")
        .unwrap();
        let first_response = String::from_utf8_lossy(&first_response[..n]);
        assert!(first_response.contains("200 OK"));

        engine.reload(TEST_POLICY, policy_data).unwrap();
        app.write_all(
            b"GET /second HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("passthrough relay should close stale tunnel")
            .unwrap()
            .unwrap();

        let mut second_upstream = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut second_upstream),
        )
        .await
        .expect("upstream side should close")
        .unwrap();
        assert_eq!(
            n, 0,
            "stale passthrough request must not be forwarded upstream"
        );
    }

    #[tokio::test]
    async fn jsonrpc_relay_forwards_allowed_method() {
        let (config, tunnel_engine, ctx) = jsonrpc_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: jsonrpc.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut upstream_bytes = Vec::new();
        let mut upstream_buf = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                upstream.read(&mut upstream_buf),
            )
            .await
            .expect("allowed JSON-RPC request should reach upstream")
            .unwrap();
            assert_ne!(n, 0, "upstream closed before JSON-RPC body arrived");
            upstream_bytes.extend_from_slice(&upstream_buf[..n]);
            if String::from_utf8_lossy(&upstream_bytes).contains(r#""method":"initialize""#) {
                break;
            }
        }
        let upstream_request = String::from_utf8_lossy(&upstream_bytes);
        assert!(upstream_request.starts_with("POST /rpc HTTP/1.1"));
        assert!(upstream_request.contains(r#""method":"initialize""#));

        upstream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 36\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            )
            .await
            .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("upstream response should reach client")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("200 OK"));

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn mcp_relay_forwards_jsonrpc_response_frame() {
        let (config, tunnel_engine, ctx) = mcp_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":7,"result":{"action":"accept","content":{}}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut upstream_buf = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut upstream_buf),
        )
        .await
        .expect("MCP response frame should reach upstream")
        .unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_buf[..n]);
        assert!(upstream_request.starts_with("POST /mcp HTTP/1.1"));
        assert!(upstream_request.contains(r#""result":{"action":"accept""#));

        upstream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), app.read(&mut response))
            .await
            .expect("upstream response should reach client")
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("202 Accepted"));

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn authenticated_mcp_delete_rewrites_credential_and_relays_405() {
        let (config, tunnel_engine, ctx, placeholder) = authenticated_mcp_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            format!(
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {placeholder}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 2048];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream.read(&mut forwarded),
        )
        .await
        .expect("valid MCP DELETE should reach upstream")
        .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]);
        assert!(forwarded.starts_with("DELETE /mcp HTTP/1.1\r\n"));
        assert!(forwarded.contains("MCP-Session-Id: session-123\r\n"));
        assert!(forwarded.contains("Authorization: Bearer mcp-real-secret\r\n"));
        assert!(!forwarded.contains(&placeholder));

        upstream
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let n = app.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("405 Method Not Allowed"));
        drop(app);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn selected_mcp_route_rejects_encoded_slash_despite_rest_opt_in() {
        for encoded_slash in ["%2f", "%2F"] {
            let (configs, tunnel_engine, ctx, placeholder) = mixed_encoded_slash_route_context();
            let (mut app, mut relay_client) = tokio::io::duplex(8192);
            let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
            let relay = tokio::spawn(async move {
                relay_with_route_selection(
                    &configs,
                    tunnel_engine,
                    &mut relay_client,
                    &mut relay_upstream,
                    &ctx,
                )
                .await
            });
            let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
            app.write_all(
                format!(
                    "POST /mcp{encoded_slash}tenant HTTP/1.1\r\nHost: gateway.example.test\r\nAuthorization: Bearer {placeholder}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            app.write_all(body).await.unwrap();
            app.shutdown().await.unwrap();
            let _ = relay.await.unwrap();

            let mut leaked = Vec::new();
            upstream.read_to_end(&mut leaked).await.unwrap();
            assert!(leaked.is_empty(), "encoded slash reached MCP upstream");
            assert!(!String::from_utf8_lossy(&leaked).contains("mcp-real-secret"));
        }
    }

    #[tokio::test]
    async fn selected_rest_route_preserves_its_encoded_slash_opt_in() {
        let (configs, tunnel_engine, ctx, _) = mixed_encoded_slash_route_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_route_selection(
                &configs,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });
        app.write_all(
            b"GET /rest/team%2Frepo HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut forwarded = [0u8; 1024];
        let n = upstream.read(&mut forwarded).await.unwrap();
        if n == 0 {
            let result = relay.await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            panic!(
                "opted-in REST route closed before forwarding: {result:?}; response={:?}",
                String::from_utf8_lossy(&response)
            );
        }
        let forwarded_text = String::from_utf8_lossy(&forwarded[..n]);
        assert!(
            forwarded_text.starts_with("GET /rest/team%2Frepo HTTP/1.1"),
            "forwarded request: {forwarded_text:?}"
        );
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 256];
        let n = app.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("200 OK"));
        drop(app);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_or_unauthorized_mcp_delete_writes_zero_upstream_bytes() {
        let variants = [
            (
                "missing session",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "duplicate session",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: one\r\nmcp-session-id: two\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "invalid session",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: has space\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "nonempty body",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                false,
            ),
            (
                "query",
                "DELETE /mcp?token=forbidden HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "empty query delimiter",
                "DELETE /mcp? HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "canonicalized empty query delimiter",
                "DELETE /a/../mcp? HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "wrong path",
                "DELETE /other HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "wrong host",
                "DELETE /mcp HTTP/1.1\r\nHost: attacker.example:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "whitespace before host colon",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nHost : attacker.example:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "tab before host colon",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nHost\t: attacker.example:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "credential in session header",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: {token}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "credential in custom header",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nX-Reflected-Token: {token}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "basic authorization",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Basic e3Rva2VufQ==\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "duplicate authorization",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nauthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "content length plus gzip transfer encoding",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "content length plus identity transfer encoding",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "whitespace before content length colon",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length : 0\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "whitespace before transfer encoding colon",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nTransfer-Encoding : chunked\r\nConnection: close\r\n\r\n",
                false,
            ),
            (
                "NUL in header",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nX-Bad: before\0after\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
            (
                "bare carriage return",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nX-Bad: before\rafter\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
            (
                "tab separated request line",
                "DELETE\t/mcp\tHTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
            (
                "vertical tab request line",
                "DELETE\u{000b}/mcp\u{000b}HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
            (
                "wrong binary",
                "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                true,
            ),
        ];

        for (name, template, wrong_binary) in variants {
            let (config, tunnel_engine, mut ctx, placeholder) =
                authenticated_mcp_test_relay_context();
            if wrong_binary {
                ctx.binary_path = "/usr/bin/curl".to_string();
            }
            let (mut app, mut relay_client) = tokio::io::duplex(8192);
            let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
            let relay = tokio::spawn(async move {
                relay_with_inspection(
                    &config,
                    tunnel_engine,
                    &mut relay_client,
                    &mut relay_upstream,
                    &ctx,
                )
                .await
            });
            app.write_all(template.replace("{token}", &placeholder).as_bytes())
                .await
                .unwrap();
            app.shutdown().await.unwrap();
            let _ = relay.await.unwrap();

            let mut leaked = Vec::new();
            upstream.read_to_end(&mut leaked).await.unwrap();
            assert!(leaked.is_empty(), "{name} reached upstream: {leaked:?}");
            assert!(
                !String::from_utf8_lossy(&leaked).contains("mcp-real-secret"),
                "{name} leaked the bound credential"
            );
        }
    }

    #[tokio::test]
    async fn bound_mcp_without_live_resolver_still_enforces_host_and_origin_form() {
        let invalid_requests = [
            "DELETE https://mcp.example.test:8000/mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nContent-Length: 0\r\n\r\n",
            "DELETE mcp.example.test:8000 HTTP/1.1\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nContent-Length: 0\r\n\r\n",
            "DELETE /mcp HTTP/1.1\r\nMCP-Session-Id: session-123\r\nContent-Length: 0\r\n\r\n",
            "DELETE /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nHost: mcp.example.test:8000\r\nMCP-Session-Id: session-123\r\nContent-Length: 0\r\n\r\n",
            "DELETE /mcp HTTP/1.1\r\nHost: attacker.example:8000\r\nMCP-Session-Id: session-123\r\nContent-Length: 0\r\n\r\n",
        ];

        for raw in invalid_requests {
            let (config, tunnel_engine, mut ctx, _) = authenticated_mcp_test_relay_context();
            ctx.secret_resolver = None;
            let (mut app, mut relay_client) = tokio::io::duplex(8192);
            let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
            let relay = tokio::spawn(async move {
                relay_with_inspection(
                    &config,
                    tunnel_engine,
                    &mut relay_client,
                    &mut relay_upstream,
                    &ctx,
                )
                .await
            });
            app.write_all(raw.as_bytes()).await.unwrap();
            app.shutdown().await.unwrap();
            relay.await.unwrap().unwrap();

            let mut leaked = Vec::new();
            upstream.read_to_end(&mut leaked).await.unwrap();
            assert!(
                leaked.is_empty(),
                "invalid boundary reached upstream: {raw}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_relay_rejects_nonempty_query_without_upstream_bytes() {
        let (config, tunnel_engine, ctx) = mcp_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let request = format!(
            "POST /mcp?token=forbidden HTTP/1.1\r\nHost: mcp.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut response = [0u8; 512];
        let n = app.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("403"));
        relay.await.unwrap().unwrap();

        let mut leaked = Vec::new();
        upstream.read_to_end(&mut leaked).await.unwrap();
        assert!(leaked.is_empty(), "MCP query request reached upstream");
    }

    #[tokio::test]
    async fn mcp_credential_rewrite_rejects_mismatched_host_without_upstream_bytes() {
        let (config, tunnel_engine, mut ctx) = mcp_test_relay_context();
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("MCP_TOKEN".to_string(), "mcp-real-secret".to_string())).collect(),
        );
        ctx.secret_resolver = resolver.map(Arc::new);
        let placeholder = child_env.get("MCP_TOKEN").unwrap();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: attacker.example:8000\r\nAuthorization: Bearer {placeholder}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut response = [0u8; 512];
        let n = app.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("403"));
        relay.await.unwrap().unwrap();

        let mut leaked = Vec::new();
        upstream.read_to_end(&mut leaked).await.unwrap();
        assert!(leaked.is_empty(), "Host mismatch reached upstream");
    }

    #[tokio::test]
    async fn mcp_credential_rewrite_rejects_canonicalizing_absolute_target_without_upstream_bytes()
    {
        let (config, tunnel_engine, mut ctx) = mcp_test_relay_context();
        let (_, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("MCP_TOKEN".to_string(), "mcp-real-secret".to_string())).collect(),
        );
        ctx.secret_resolver = resolver.map(Arc::new);
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        app.write_all(
            b"POST https://attacker.example/public/../mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        app.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();

        let mut leaked = Vec::new();
        upstream.read_to_end(&mut leaked).await.unwrap();
        assert!(
            leaked.is_empty(),
            "canonicalizing absolute-form target reached upstream"
        );
    }

    #[tokio::test]
    async fn credential_rewrite_host_and_target_negatives_write_zero_upstream_bytes() {
        let (_, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("MCP_TOKEN".to_string(), "mcp-real-secret".to_string())).collect(),
        );
        let resolver = resolver.unwrap();
        for raw in [
            "POST /mcp HTTP/1.1\r\nAuthorization: Bearer provider.v1-OPENSHELL-RESOLVE-ENV-MCP_TOKEN\r\nContent-Length: 0\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\nHost: mcp.example.test\r\nAuthorization: Bearer provider.v1-OPENSHELL-RESOLVE-ENV-MCP_TOKEN\r\nContent-Length: 0\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer provider.v1-OPENSHELL-RESOLVE-ENV-MCP_TOKEN\r\nContent-Length: 0\r\n\r\n",
            "POST https://attacker.example/mcp HTTP/1.1\r\nHost: mcp.example.test\r\nAuthorization: Bearer provider.v1-OPENSHELL-RESOLVE-ENV-MCP_TOKEN\r\nContent-Length: 0\r\n\r\n",
        ] {
            let req = crate::l7::provider::L7Request {
                action: "POST".into(),
                target: "/mcp".into(),
                query_params: std::collections::HashMap::new(),
                raw_header: raw.as_bytes().to_vec(),
                body_length: crate::l7::provider::BodyLength::ContentLength(0),
                raw_target: String::new(),
            };
            let (mut _app, mut proxy_client) = tokio::io::duplex(1024);
            let (mut proxy_upstream, mut upstream) = tokio::io::duplex(1024);
            let result = crate::l7::rest::relay_http_request_with_options_guarded(
                &req,
                &mut proxy_client,
                &mut proxy_upstream,
                crate::l7::rest::RelayRequestOptions {
                    resolver: Some(&resolver),
                    host: "mcp.example.test",
                    port: 443,
                    http_default_port: 443,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_err(), "invalid credential boundary was accepted");
            drop(proxy_upstream);
            let mut leaked = Vec::new();
            upstream.read_to_end(&mut leaked).await.unwrap();
            assert!(leaked.is_empty(), "invalid request reached upstream");
        }
    }

    #[tokio::test]
    async fn tls_required_mcp_relay_rewrites_credentials_for_bound_host() {
        let (mut config, tunnel_engine, mut ctx) = mcp_test_relay_context();
        config.tls = crate::l7::TlsMode::Require;
        let (child_env, resolver) = SecretResolver::from_provider_env(
            std::iter::once(("MCP_TOKEN".to_string(), "mcp-real-secret".to_string())).collect(),
        );
        ctx.secret_resolver = resolver.map(Arc::new);
        let placeholder = child_env.get("MCP_TOKEN").unwrap();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"openshell-test","version":"1.0"}}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nAuthorization: Bearer {placeholder}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut upstream_buf = [0u8; 1024];
        let n = upstream.read(&mut upstream_buf).await.unwrap();
        if n == 0 {
            let result = relay.await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            panic!(
                "MCP relay closed before forwarding: {result:?}; response={:?}",
                String::from_utf8_lossy(&response)
            );
        }
        let forwarded = String::from_utf8_lossy(&upstream_buf[..n]);
        assert!(
            forwarded.contains("Authorization: Bearer mcp-real-secret\r\n"),
            "forwarded request: {forwarded:?}"
        );
        assert!(!forwarded.contains(placeholder));
        upstream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = [0u8; 512];
        let n = app.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("202 Accepted"));
        drop(app);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn jsonrpc_relay_denies_method_not_in_allow_list() {
        let (config, tunnel_engine, ctx) = jsonrpc_test_relay_context();
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            relay_with_inspection(
                &config,
                tunnel_engine,
                &mut relay_client,
                &mut relay_upstream,
                &ctx,
            )
            .await
        });

        let body =
            br#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"list_repos"}}"#;
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: jsonrpc.example.test:8000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        app.write_all(request.as_bytes()).await.unwrap();
        app.write_all(body).await.unwrap();

        let mut response = [0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), app.read(&mut response))
            .await
            .expect("relay should respond without reaching upstream")
            .unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(
            response.contains("403"),
            "reports.search not in allow list must be denied with 403, got: {response:?}"
        );

        let mut upstream_buf = [0u8; 128];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            upstream.read(&mut upstream_buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
        assert_eq!(n, 0, "denied request must not be forwarded to upstream");

        drop(app);
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay should complete")
            .unwrap()
            .unwrap();
    }
}
