// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_SUPERVISOR_IMAGE;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

/// Default Kubernetes namespace for sandbox resources.
pub const DEFAULT_K8S_NAMESPACE: &str = "openshell";

/// Default Kubernetes `ServiceAccount` assigned to sandbox pods.
pub const DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME: &str = "default";

/// Default storage size for the workspace PVC.
pub const DEFAULT_WORKSPACE_STORAGE_SIZE: &str = "2Gi";

/// Default shared volume name for sandbox log collection.
pub const DEFAULT_SANDBOX_LOG_VOLUME_NAME: &str = "openshell-logs";

/// Default agent mount path for sandbox log collection.
pub const DEFAULT_SANDBOX_LOG_MOUNT_PATH: &str = "/var/log/openshell";

/// Default Kubernetes sidecar name for sandbox log collection.
pub const DEFAULT_LOG_COLLECTION_SIDECAR_NAME: &str = "openshell-log-collector";

const GENERATED_VOLUME_NAMES: &[&str] = &[
    "openshell-client-tls",
    "openshell-sa-token",
    "spiffe-workload-api",
    "workspace",
    "openshell-supervisor-bin",
];

const GENERATED_CONTAINER_NAMES: &[&str] =
    &["agent", "openshell-supervisor-install", "workspace-init"];

/// How the supervisor binary is delivered into sandbox pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorSideloadMethod {
    /// Mount the supervisor OCI image directly as a read-only volume
    /// (requires Kubernetes >= v1.33 with the `ImageVolume` feature gate,
    /// or >= v1.36 where it is GA).
    #[default]
    ImageVolume,
    /// Copy the binary via an init container and emptyDir volume.
    /// Works on all Kubernetes versions.
    InitContainer,
}

impl std::fmt::Display for SupervisorSideloadMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImageVolume => f.write_str("image-volume"),
            Self::InitContainer => f.write_str("init-container"),
        }
    }
}

impl FromStr for SupervisorSideloadMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "image-volume" => Ok(Self::ImageVolume),
            "init-container" => Ok(Self::InitContainer),
            other => Err(format!(
                "unknown supervisor sideload method '{other}'; expected 'image-volume' or 'init-container'"
            )),
        }
    }
}

/// Kubernetes `AppArmor` profile requested for the sandbox agent container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArmorProfile {
    RuntimeDefault,
    Unconfined,
    Localhost(String),
}

impl AppArmorProfile {
    #[must_use]
    pub fn to_k8s_type(&self) -> &'static str {
        match self {
            Self::RuntimeDefault => "RuntimeDefault",
            Self::Unconfined => "Unconfined",
            Self::Localhost(_) => "Localhost",
        }
    }

    #[must_use]
    pub fn localhost_profile(&self) -> Option<&str> {
        match self {
            Self::Localhost(profile) => Some(profile),
            Self::RuntimeDefault | Self::Unconfined => None,
        }
    }
}

impl std::fmt::Display for AppArmorProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeDefault => f.write_str("RuntimeDefault"),
            Self::Unconfined => f.write_str("Unconfined"),
            Self::Localhost(profile) => write!(f, "Localhost/{profile}"),
        }
    }
}

impl FromStr for AppArmorProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "RuntimeDefault" => Ok(Self::RuntimeDefault),
            "Unconfined" => Ok(Self::Unconfined),
            other => match other.strip_prefix("Localhost/") {
                Some("") => Err(
                    "invalid AppArmor profile 'Localhost/'; expected non-empty profile name"
                        .to_string(),
                ),
                Some(profile) => Ok(Self::Localhost(profile.to_string())),
                None => Err(format!(
                    "unknown AppArmor profile '{other}'; expected 'RuntimeDefault', 'Unconfined', or 'Localhost/<profile-name>'"
                )),
            },
        }
    }
}

impl Serialize for AppArmorProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AppArmorProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn deserialize_optional_app_armor_profile<'de, D>(
    deserializer: D,
) -> Result<Option<AppArmorProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref() {
        None | Some("") => Ok(None),
        Some(value) => AppArmorProfile::from_str(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn deserialize_provider_spiffe_workload_api_socket_path<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_provider_spiffe_workload_api_socket_path_value(&value)
        .map_err(serde::de::Error::custom)?;
    Ok(value)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesPodExtensionsConfig {
    /// Operator-owned volumes made available to agent mounts and sidecars.
    pub volumes: Vec<KubernetesPodExtensionVolume>,
    /// Operator-owned volume mounts added to the agent container.
    pub agent_volume_mounts: Vec<KubernetesPodExtensionVolumeMount>,
    /// Operator-owned sidecar containers added to every sandbox pod.
    pub sidecars: Vec<KubernetesPodExtensionSidecar>,
}

impl KubernetesPodExtensionsConfig {
    pub fn validate(&self) -> Result<(), String> {
        let mut volume_names = BTreeSet::new();
        for (idx, volume) in self.volumes.iter().enumerate() {
            volume.validate(idx)?;
            if GENERATED_VOLUME_NAMES.contains(&volume.name.as_str()) {
                return Err(format!(
                    "pod_extensions.volumes[{idx}].name '{}' conflicts with generated OpenShell volume",
                    volume.name
                ));
            }
            if !volume_names.insert(volume.name.clone()) {
                return Err(format!(
                    "pod_extensions.volumes[{idx}].name '{}' is duplicated",
                    volume.name
                ));
            }
        }

        for (idx, mount) in self.agent_volume_mounts.iter().enumerate() {
            mount.validate(&format!("pod_extensions.agent_volume_mounts[{idx}]"))?;
            if !volume_names.contains(&mount.name) {
                return Err(format!(
                    "pod_extensions.agent_volume_mounts[{idx}].name '{}' does not reference a pod_extensions volume",
                    mount.name
                ));
            }
        }

        let mut container_names = BTreeSet::new();
        for (idx, sidecar) in self.sidecars.iter().enumerate() {
            sidecar.validate(idx, &volume_names)?;
            if GENERATED_CONTAINER_NAMES.contains(&sidecar.name.as_str()) {
                return Err(format!(
                    "pod_extensions.sidecars[{idx}].name '{}' conflicts with generated OpenShell container",
                    sidecar.name
                ));
            }
            if !container_names.insert(sidecar.name.clone()) {
                return Err(format!(
                    "pod_extensions.sidecars[{idx}].name '{}' is duplicated",
                    sidecar.name
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesPodExtensionVolume {
    pub name: String,
    /// Render an emptyDir volume. Exactly one volume source must be set.
    pub empty_dir: bool,
    /// Render a `ConfigMap` volume with this `ConfigMap` name.
    pub config_map_name: String,
    /// Render a `Secret` volume with this `Secret` name.
    pub secret_name: String,
}

impl KubernetesPodExtensionVolume {
    fn validate(&self, idx: usize) -> Result<(), String> {
        validate_k8s_name(&self.name, &format!("pod_extensions.volumes[{idx}].name"))?;
        let source_count = usize::from(self.empty_dir)
            + usize::from(!self.config_map_name.trim().is_empty())
            + usize::from(!self.secret_name.trim().is_empty());
        if source_count != 1 {
            return Err(format!(
                "pod_extensions.volumes[{idx}] must set exactly one of empty_dir, config_map_name, or secret_name"
            ));
        }
        if !self.config_map_name.trim().is_empty() {
            validate_k8s_name(
                &self.config_map_name,
                &format!("pod_extensions.volumes[{idx}].config_map_name"),
            )?;
        }
        if !self.secret_name.trim().is_empty() {
            validate_k8s_name(
                &self.secret_name,
                &format!("pod_extensions.volumes[{idx}].secret_name"),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesPodExtensionVolumeMount {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

impl KubernetesPodExtensionVolumeMount {
    fn validate(&self, field: &str) -> Result<(), String> {
        validate_k8s_name(&self.name, &format!("{field}.name"))?;
        openshell_core::driver_mounts::validate_container_mount_target(&self.mount_path)
            .map_err(|err| format!("{field}.mount_path invalid: {err}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesPodExtensionSidecar {
    pub name: String,
    pub image: String,
    pub image_pull_policy: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub volume_mounts: Vec<KubernetesPodExtensionVolumeMount>,
    pub resources: KubernetesResourceConfig,
}

impl KubernetesPodExtensionSidecar {
    fn validate(&self, idx: usize, volume_names: &BTreeSet<String>) -> Result<(), String> {
        let field = format!("pod_extensions.sidecars[{idx}]");
        validate_k8s_name(&self.name, &format!("{field}.name"))?;
        validate_nonempty_string(&self.image, &format!("{field}.image"))?;
        validate_image_pull_policy(
            &self.image_pull_policy,
            &format!("{field}.image_pull_policy"),
        )?;
        validate_resource_config(&self.resources, &format!("{field}.resources"))?;
        for (mount_idx, mount) in self.volume_mounts.iter().enumerate() {
            let mount_field = format!("{field}.volume_mounts[{mount_idx}]");
            mount.validate(&mount_field)?;
            if !volume_names.contains(&mount.name) {
                return Err(format!(
                    "{mount_field}.name '{}' does not reference a pod_extensions volume",
                    mount.name
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesResourceConfig {
    pub requests: BTreeMap<String, String>,
    pub limits: BTreeMap<String, String>,
}

impl KubernetesResourceConfig {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty() && self.limits.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesLogCollectionConfig {
    /// Enable the shared log volume and set `OPENSHELL_LOG_DIR` on the agent.
    pub enabled: bool,
    /// Shared volume name used for sandbox log files.
    pub volume_name: String,
    /// Mount path used by the agent and collector sidecar.
    pub mount_path: String,
    /// Optional collector sidecar mounted read-only at `mount_path`.
    pub sidecar: KubernetesLogCollectionSidecarConfig,
}

impl Default for KubernetesLogCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            volume_name: DEFAULT_SANDBOX_LOG_VOLUME_NAME.to_string(),
            mount_path: DEFAULT_SANDBOX_LOG_MOUNT_PATH.to_string(),
            sidecar: KubernetesLogCollectionSidecarConfig::default(),
        }
    }
}

impl KubernetesLogCollectionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled && !self.sidecar.enabled {
            return Ok(());
        }
        if self.sidecar.enabled && !self.enabled {
            return Err(
                "log_collection.sidecar.enabled requires log_collection.enabled".to_string(),
            );
        }
        validate_k8s_name(&self.volume_name, "log_collection.volume_name")?;
        if GENERATED_VOLUME_NAMES.contains(&self.volume_name.as_str()) {
            return Err(format!(
                "log_collection.volume_name '{}' conflicts with generated OpenShell volume",
                self.volume_name
            ));
        }
        openshell_core::driver_mounts::validate_container_mount_target(&self.mount_path)
            .map_err(|err| format!("log_collection.mount_path invalid: {err}"))?;
        self.sidecar.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesLogCollectionSidecarConfig {
    pub enabled: bool,
    pub name: String,
    pub image: String,
    pub image_pull_policy: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Additional mounts for operator-owned `pod_extensions` volumes.
    pub volume_mounts: Vec<KubernetesPodExtensionVolumeMount>,
    pub resources: KubernetesResourceConfig,
}

impl Default for KubernetesLogCollectionSidecarConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: DEFAULT_LOG_COLLECTION_SIDECAR_NAME.to_string(),
            image: String::new(),
            image_pull_policy: String::new(),
            command: Vec::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            volume_mounts: Vec::new(),
            resources: KubernetesResourceConfig::default(),
        }
    }
}

impl KubernetesLogCollectionSidecarConfig {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        validate_k8s_name(&self.name, "log_collection.sidecar.name")?;
        if GENERATED_CONTAINER_NAMES.contains(&self.name.as_str()) {
            return Err(format!(
                "log_collection.sidecar.name '{}' conflicts with generated OpenShell container",
                self.name
            ));
        }
        validate_nonempty_string(&self.image, "log_collection.sidecar.image")?;
        validate_image_pull_policy(
            &self.image_pull_policy,
            "log_collection.sidecar.image_pull_policy",
        )?;
        for (idx, mount) in self.volume_mounts.iter().enumerate() {
            mount.validate(&format!("log_collection.sidecar.volume_mounts[{idx}]"))?;
        }
        validate_resource_config(&self.resources, "log_collection.sidecar.resources")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesComputeConfig {
    pub namespace: String,
    /// Kubernetes `ServiceAccount` assigned to sandbox pods and accepted by
    /// the gateway's `TokenReview` bootstrap authenticator.
    pub service_account_name: String,
    pub default_image: String,
    pub image_pull_policy: String,
    /// Kubernetes `imagePullSecrets` names attached to sandbox pods.
    pub image_pull_secrets: Vec<String>,
    /// Image that provides the `openshell-sandbox` supervisor binary.
    /// Mounted directly as an image volume, or copied via an init container,
    /// depending on `supervisor_sideload_method`.
    pub supervisor_image: String,
    /// Kubernetes `imagePullPolicy` for the supervisor image.
    /// Empty string delegates to the Kubernetes default.
    pub supervisor_image_pull_policy: String,
    /// How the supervisor binary is delivered into sandbox pods.
    pub supervisor_sideload_method: SupervisorSideloadMethod,
    pub grpc_endpoint: String,
    pub ssh_socket_path: String,
    pub client_tls_secret_name: String,
    pub host_gateway_ip: String,
    pub enable_user_namespaces: bool,
    /// Kubernetes `AppArmor` profile requested for the sandbox agent container.
    /// Empty/None omits the `appArmorProfile` field from sandbox pod specs.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_app_armor_profile"
    )]
    pub app_armor_profile: Option<AppArmorProfile>,
    pub workspace_default_storage_size: String,
    /// Default Kubernetes `runtimeClassName` for sandbox pods.
    /// Applied when a `CreateSandbox` request does not specify one.
    /// Empty string (default) = omit the field, using the cluster default.
    pub default_runtime_class_name: String,
    /// Lifetime (seconds) of the projected `ServiceAccount` token kubelet
    /// writes into each sandbox pod. Used only for the one-shot
    /// `IssueSandboxToken` bootstrap exchange — the gateway-minted JWT
    /// that follows has its own TTL set via `gateway_jwt.ttl_secs`.
    ///
    /// Kubelet enforces a minimum of 600 seconds; the supervisor uses
    /// this token within a few seconds of pod start, so any value at
    /// the floor is sufficient. Default 3600.
    pub sa_token_ttl_secs: i64,
    /// SPIFFE Workload API socket path mounted into sandbox pods for dynamic
    /// provider token grants. Empty disables provider token-grant SPIFFE
    /// material.
    #[serde(
        default,
        deserialize_with = "deserialize_provider_spiffe_workload_api_socket_path"
    )]
    pub provider_spiffe_workload_api_socket_path: String,
    /// Operator-owned sandbox pod extensions.
    pub pod_extensions: KubernetesPodExtensionsConfig,
    /// File-backed sandbox log collection settings.
    pub log_collection: KubernetesLogCollectionConfig,
}

/// Lower bound enforced by kubelet for projected SA tokens.
pub const MIN_SA_TOKEN_TTL_SECS: i64 = 600;

/// Cap at 24h — operators who want longer-lived bootstrap tokens are
/// almost certainly misconfigured (the token is consumed seconds after
/// pod start).
pub const MAX_SA_TOKEN_TTL_SECS: i64 = 86_400;

impl Default for KubernetesComputeConfig {
    fn default() -> Self {
        Self {
            namespace: DEFAULT_K8S_NAMESPACE.to_string(),
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME.to_string(),
            default_image: openshell_core::image::default_sandbox_image(),
            // Default empty so the gateway omits `imagePullPolicy` from pod
            // specs and Kubernetes applies its own default (Always for `latest`,
            // IfNotPresent otherwise). `DEFAULT_IMAGE_PULL_POLICY` ("missing")
            // is Podman vocabulary and is not a valid Kubernetes value.
            image_pull_policy: String::new(),
            image_pull_secrets: Vec::new(),
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
            supervisor_image_pull_policy: String::new(),
            supervisor_sideload_method: SupervisorSideloadMethod::default(),
            grpc_endpoint: String::new(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            client_tls_secret_name: String::new(),
            host_gateway_ip: String::new(),
            enable_user_namespaces: false,
            app_armor_profile: None,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE.to_string(),
            default_runtime_class_name: String::new(),
            sa_token_ttl_secs: 3600,
            provider_spiffe_workload_api_socket_path: String::new(),
            pod_extensions: KubernetesPodExtensionsConfig::default(),
            log_collection: KubernetesLogCollectionConfig::default(),
        }
    }
}

impl KubernetesComputeConfig {
    /// Clamp `sa_token_ttl_secs` into the `[MIN_SA_TOKEN_TTL_SECS,
    /// MAX_SA_TOKEN_TTL_SECS]` range used by the projected-volume spec.
    /// Invalid (≤0) values fall back to the default 3600.
    #[must_use]
    pub fn effective_sa_token_ttl_secs(&self) -> i64 {
        if self.sa_token_ttl_secs <= 0 {
            3600
        } else {
            self.sa_token_ttl_secs
                .clamp(MIN_SA_TOKEN_TTL_SECS, MAX_SA_TOKEN_TTL_SECS)
        }
    }

    #[must_use]
    pub fn provider_spiffe_enabled(&self) -> bool {
        !self
            .provider_spiffe_workload_api_socket_path
            .trim()
            .is_empty()
    }

    pub fn validate_provider_spiffe_workload_api_socket_path(&self) -> Result<(), String> {
        validate_provider_spiffe_workload_api_socket_path_value(
            &self.provider_spiffe_workload_api_socket_path,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_provider_spiffe_workload_api_socket_path()?;
        self.pod_extensions.validate()?;
        self.log_collection.validate()?;
        validate_extension_log_collection_conflicts(&self.pod_extensions, &self.log_collection)
    }
}

fn validate_provider_spiffe_workload_api_socket_path_value(
    socket_path: &str,
) -> Result<(), String> {
    let trimmed = socket_path.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed != socket_path {
        return Err(
            "provider_spiffe_workload_api_socket_path must not contain leading or trailing whitespace"
                .to_string(),
        );
    }
    let path = Path::new(socket_path);
    if !path.is_absolute() {
        return Err(
            "provider_spiffe_workload_api_socket_path must be an absolute UNIX socket path"
                .to_string(),
        );
    }
    let parent = path.parent().ok_or_else(|| {
        "provider_spiffe_workload_api_socket_path must include a parent directory".to_string()
    })?;
    if parent == Path::new("/") {
        return Err(
            "provider_spiffe_workload_api_socket_path must live below a dedicated directory"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_extension_log_collection_conflicts(
    extensions: &KubernetesPodExtensionsConfig,
    log_collection: &KubernetesLogCollectionConfig,
) -> Result<(), String> {
    if !log_collection.enabled {
        return Ok(());
    }
    for (idx, volume) in extensions.volumes.iter().enumerate() {
        if volume.name == log_collection.volume_name {
            return Err(format!(
                "pod_extensions.volumes[{idx}].name '{}' conflicts with log_collection.volume_name",
                volume.name
            ));
        }
    }
    for (idx, sidecar) in extensions.sidecars.iter().enumerate() {
        if log_collection.sidecar.enabled && sidecar.name == log_collection.sidecar.name {
            return Err(format!(
                "pod_extensions.sidecars[{idx}].name '{}' conflicts with log_collection.sidecar.name",
                sidecar.name
            ));
        }
    }
    for (idx, mount) in extensions.agent_volume_mounts.iter().enumerate() {
        if mount_paths_overlap(&mount.mount_path, &log_collection.mount_path) {
            return Err(format!(
                "pod_extensions.agent_volume_mounts[{idx}].mount_path '{}' overlaps log_collection.mount_path '{}'",
                mount.mount_path, log_collection.mount_path
            ));
        }
    }
    let extension_volume_names = extensions
        .volumes
        .iter()
        .map(|volume| volume.name.clone())
        .collect::<BTreeSet<_>>();
    for (idx, mount) in log_collection.sidecar.volume_mounts.iter().enumerate() {
        if !extension_volume_names.contains(&mount.name) {
            return Err(format!(
                "log_collection.sidecar.volume_mounts[{idx}].name '{}' does not reference a pod_extensions volume",
                mount.name
            ));
        }
        if mount_paths_overlap(&mount.mount_path, &log_collection.mount_path) {
            return Err(format!(
                "log_collection.sidecar.volume_mounts[{idx}].mount_path '{}' overlaps log_collection.mount_path '{}'",
                mount.mount_path, log_collection.mount_path
            ));
        }
    }
    Ok(())
}

fn validate_k8s_name(value: &str, field: &str) -> Result<(), String> {
    validate_nonempty_string(value, field)?;
    if value != value.trim() {
        return Err(format!(
            "{field} must not contain leading or trailing whitespace"
        ));
    }
    if value.len() > 63 {
        return Err(format!("{field} must be 63 characters or less"));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(format!("{field} must not be empty"));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "{field} must start with a lowercase letter or digit"
        ));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(format!(
            "{field} must contain only lowercase letters, digits, or '-'"
        ));
    }
    if value.ends_with('-') {
        return Err(format!("{field} must end with a lowercase letter or digit"));
    }
    Ok(())
}

fn validate_nonempty_string(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.as_bytes().contains(&0) {
        return Err(format!("{field} must not contain NUL bytes"));
    }
    Ok(())
}

fn validate_image_pull_policy(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || matches!(value, "Always" | "IfNotPresent" | "Never") {
        return Ok(());
    }
    Err(format!(
        "{field} must be one of Always, IfNotPresent, Never, or empty"
    ))
}

fn validate_resource_config(
    resources: &KubernetesResourceConfig,
    field: &str,
) -> Result<(), String> {
    for (section, values) in [
        ("requests", &resources.requests),
        ("limits", &resources.limits),
    ] {
        for (key, value) in values {
            validate_nonempty_string(key, &format!("{field}.{section} key"))?;
            validate_nonempty_string(value, &format!("{field}.{section}.{key}"))?;
        }
    }
    Ok(())
}

fn mount_paths_overlap(left: &str, right: &str) -> bool {
    path_is_or_under(left, right) || path_is_or_under(right, left)
}

fn path_is_or_under(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workspace_storage_size_is_2gi() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.workspace_default_storage_size,
            DEFAULT_WORKSPACE_STORAGE_SIZE
        );
    }

    #[test]
    fn default_service_account_name_is_default() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.service_account_name,
            DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
        );
    }

    #[test]
    fn serde_override_workspace_storage_size() {
        let json = serde_json::json!({
            "workspace_default_storage_size": "10Gi"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_default_storage_size, "10Gi");
    }

    #[test]
    fn serde_override_service_account_name() {
        let json = serde_json::json!({
            "service_account_name": "openshell-sandbox"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.service_account_name, "openshell-sandbox");
    }

    #[test]
    fn serde_override_default_runtime_class_name() {
        let json = serde_json::json!({
            "default_runtime_class_name": "nvidia"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.default_runtime_class_name, "nvidia");
    }

    #[test]
    fn default_runtime_class_name_is_empty() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.default_runtime_class_name.is_empty());
    }

    #[test]
    fn default_app_armor_profile_is_none() {
        let cfg = KubernetesComputeConfig::default();
        assert!(cfg.app_armor_profile.is_none());
    }

    #[test]
    fn serde_override_app_armor_profile_unconfined() {
        let json = serde_json::json!({
            "app_armor_profile": "Unconfined"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, Some(AppArmorProfile::Unconfined));
    }

    #[test]
    fn serde_override_app_armor_profile_runtime_default() {
        let json = serde_json::json!({
            "app_armor_profile": "RuntimeDefault"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, Some(AppArmorProfile::RuntimeDefault));
    }

    #[test]
    fn serde_override_app_armor_profile_localhost() {
        let json = serde_json::json!({
            "app_armor_profile": "Localhost/openshell-supervisor"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            cfg.app_armor_profile,
            Some(AppArmorProfile::Localhost(
                "openshell-supervisor".to_string()
            ))
        );
    }

    #[test]
    fn serde_empty_app_armor_profile_disables_field() {
        let json = serde_json::json!({
            "app_armor_profile": ""
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.app_armor_profile, None);
    }

    #[test]
    fn serde_accepts_absolute_provider_spiffe_socket_path() {
        let json = serde_json::json!({
            "provider_spiffe_workload_api_socket_path": "/spiffe-workload-api/spire-agent.sock"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        cfg.validate_provider_spiffe_workload_api_socket_path()
            .unwrap();
    }

    #[test]
    fn serde_rejects_invalid_provider_spiffe_socket_path() {
        for socket_path in [
            "spiffe-workload-api/spire-agent.sock",
            "/spire-agent.sock",
            " /spiffe-workload-api/spire-agent.sock",
        ] {
            let json = serde_json::json!({
                "provider_spiffe_workload_api_socket_path": socket_path
            });
            let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
            assert!(
                err.to_string()
                    .contains("provider_spiffe_workload_api_socket_path"),
                "unexpected error for {socket_path}: {err}"
            );
        }
    }

    #[test]
    fn serde_rejects_invalid_app_armor_profile() {
        let json = serde_json::json!({
            "app_armor_profile": "runtime/default"
        });
        let err = serde_json::from_value::<KubernetesComputeConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown AppArmor profile"));
    }

    #[test]
    fn serde_override_image_pull_secrets() {
        let json = serde_json::json!({
            "image_pull_secrets": ["regcred", "backup-regcred"]
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.image_pull_secrets, ["regcred", "backup-regcred"]);
    }

    #[test]
    fn default_log_collection_is_disabled_with_dedicated_path() {
        let cfg = KubernetesComputeConfig::default();

        assert!(!cfg.log_collection.enabled);
        assert_eq!(
            cfg.log_collection.volume_name,
            DEFAULT_SANDBOX_LOG_VOLUME_NAME
        );
        assert_eq!(
            cfg.log_collection.mount_path,
            DEFAULT_SANDBOX_LOG_MOUNT_PATH
        );
    }

    #[test]
    fn serde_accepts_log_collection_sidecar_with_extension_config_mount() {
        let json = serde_json::json!({
            "pod_extensions": {
                "volumes": [{
                    "name": "otel-config",
                    "config_map_name": "openshell-otel-config"
                }]
            },
            "log_collection": {
                "enabled": true,
                "sidecar": {
                    "enabled": true,
                    "name": "sandbox-log-collector",
                    "image": "otel/opentelemetry-collector-contrib:latest",
                    "image_pull_policy": "IfNotPresent",
                    "args": ["--config=/etc/otelcol/config.yaml"],
                    "volume_mounts": [{
                        "name": "otel-config",
                        "mount_path": "/etc/otelcol",
                        "read_only": true
                    }]
                }
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        cfg.validate().unwrap();
        assert!(cfg.log_collection.enabled);
        assert!(cfg.log_collection.sidecar.enabled);
        assert_eq!(cfg.pod_extensions.volumes[0].name, "otel-config");
    }

    #[test]
    fn log_collection_sidecar_requires_log_collection() {
        let json = serde_json::json!({
            "log_collection": {
                "enabled": false,
                "sidecar": {
                    "enabled": true,
                    "image": "otel/opentelemetry-collector-contrib:latest"
                }
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        let err = cfg.validate().unwrap_err();

        assert!(err.contains("log_collection.sidecar.enabled requires log_collection.enabled"));
    }

    #[test]
    fn log_collection_sidecar_requires_image() {
        let json = serde_json::json!({
            "log_collection": {
                "enabled": true,
                "sidecar": {
                    "enabled": true
                }
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        let err = cfg.validate().unwrap_err();

        assert!(err.contains("log_collection.sidecar.image"));
    }

    #[test]
    fn pod_extensions_reject_generated_volume_name_conflict() {
        let json = serde_json::json!({
            "pod_extensions": {
                "volumes": [{
                    "name": "openshell-sa-token",
                    "empty_dir": true
                }]
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        let err = cfg.validate().unwrap_err();

        assert!(err.contains("generated OpenShell volume"));
    }

    #[test]
    fn pod_extensions_reject_agent_mount_of_reserved_control_path() {
        let json = serde_json::json!({
            "pod_extensions": {
                "volumes": [{
                    "name": "bad",
                    "empty_dir": true
                }],
                "agent_volume_mounts": [{
                    "name": "bad",
                    "mount_path": "/var/run/secrets/openshell"
                }]
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        let err = cfg.validate().unwrap_err();

        assert!(err.contains("/var/run/secrets/openshell"));
    }

    #[test]
    fn log_sidecar_mounts_must_reference_extension_volumes() {
        let json = serde_json::json!({
            "log_collection": {
                "enabled": true,
                "sidecar": {
                    "enabled": true,
                    "image": "otel/opentelemetry-collector-contrib:latest",
                    "volume_mounts": [{
                        "name": "missing-config",
                        "mount_path": "/etc/otelcol"
                    }]
                }
            }
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();

        let err = cfg.validate().unwrap_err();

        assert!(err.contains("does not reference a pod_extensions volume"));
    }
}
