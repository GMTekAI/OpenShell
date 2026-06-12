// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    AttachSandboxProviderRequest, CreateProviderRequest, CreateSandboxRequest, Provider,
    SandboxPolicy, SandboxSpec, UpdateConfigRequest,
};
use tonic::Code;
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args =
        Args::parse().map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let mut client = OpenShellClient::connect(args.endpoint.clone()).await?;

    match args.case.as_str() {
        "custom-policy-rejected" => custom_policy_rejected(&mut client).await?,
        "policy-modification-rejected" => policy_modification_rejected(&mut client).await?,
        "create-base-sandbox" => create_base_sandbox(&mut client).await?,
        "attach-known-provider" => attach_known_provider(&mut client).await?,
        "new-provider-rejected" => new_provider_rejected(&mut client).await?,
        "--help" | "-h" => print_usage(),
        other => return Err(format!("unknown case: {other}").into()),
    }

    Ok(())
}

async fn custom_policy_rejected(
    client: &mut OpenShellClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = CreateSandboxRequest {
        name: "policy-source-custom-policy".to_string(),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy::default()),
            ..Default::default()
        }),
        labels: HashMap::new(),
    };
    expect_failed_precondition(
        client.create_sandbox(request).await.map(|_| ()),
        "global_policy",
    )
}

async fn policy_modification_rejected(
    client: &mut OpenShellClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = UpdateConfigRequest {
        name: "policy-source-smoke".to_string(),
        policy: Some(SandboxPolicy::default()),
        ..Default::default()
    };
    expect_failed_precondition(
        client.update_config(request).await.map(|_| ()),
        "global_policy",
    )
}

async fn create_base_sandbox(
    client: &mut OpenShellClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = CreateSandboxRequest {
        name: "policy-source-smoke".to_string(),
        spec: Some(SandboxSpec::default()),
        labels: HashMap::new(),
    };
    match client.create_sandbox(request).await {
        Ok(_) => Ok(()),
        Err(status) if status.code() == Code::AlreadyExists => Ok(()),
        Err(status) => Err(format!("create base sandbox failed: {status}").into()),
    }
}

async fn attach_known_provider(
    client: &mut OpenShellClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = AttachSandboxProviderRequest {
        sandbox_name: "policy-source-smoke".to_string(),
        provider_name: "github".to_string(),
        expected_resource_version: 0,
    };
    client
        .attach_sandbox_provider(request)
        .await
        .map(|_| ())
        .map_err(|status| format!("attach known provider failed: {status}").into())
}

async fn new_provider_rejected(
    client: &mut OpenShellClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: String::new(),
            name: "ad-hoc".to_string(),
            created_at_ms: 0,
            labels: HashMap::new(),
            resource_version: 0,
        }),
        r#type: "github".to_string(),
        credentials: HashMap::new(),
        config: HashMap::new(),
        credential_expires_at_ms: HashMap::new(),
    };
    expect_failed_precondition(
        client
            .create_provider(CreateProviderRequest {
                provider: Some(provider),
            })
            .await
            .map(|_| ()),
        "provider mutations",
    )?;

    let request = AttachSandboxProviderRequest {
        sandbox_name: "policy-source-smoke".to_string(),
        provider_name: "not-from-bundle".to_string(),
        expected_resource_version: 0,
    };
    expect_failed_precondition(
        client.attach_sandbox_provider(request).await.map(|_| ()),
        "provider 'not-from-bundle' not found",
    )
}

fn expect_failed_precondition<T>(
    result: Result<T, tonic::Status>,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(status)
            if status.code() == Code::FailedPrecondition && status.message().contains(message) =>
        {
            Ok(())
        }
        Err(status) => Err(format!("unexpected gRPC status: {status}").into()),
        Ok(_) => Err("request unexpectedly succeeded".into()),
    }
}

#[derive(Debug)]
struct Args {
    endpoint: String,
    case: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut endpoint = "http://127.0.0.1:17670".to_string();
        let mut case = String::new();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--endpoint" => {
                    endpoint = args
                        .next()
                        .ok_or_else(|| "--endpoint requires a URL".to_string())?;
                }
                "--case" => {
                    case = args
                        .next()
                        .ok_or_else(|| "--case requires a name".to_string())?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }
        if case.is_empty() {
            return Err("--case is required".to_string());
        }

        Ok(Self { endpoint, case })
    }
}

fn print_usage() {
    eprintln!(
        "usage: policy-source-gateway-check --endpoint URL --case CASE\n\n\
         cases: custom-policy-rejected, policy-modification-rejected, \
         create-base-sandbox, attach-known-provider, new-provider-rejected"
    );
}
