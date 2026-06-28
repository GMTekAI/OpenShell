// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable, gateway-owned credential-key reservations.
//!
//! A policy may stop authorizing an endpoint, but a credential key that was
//! ever endpoint-bound for a sandbox ID must remain reserved for that
//! sandbox's lifetime. Otherwise a gateway or supervisor restart could turn a
//! formerly scoped credential back into an ordinary process-visible secret.

use crate::persistence::{PersistenceError, Store, WriteCondition};
use openshell_core::proto::SandboxPolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tonic::Status;

const RESERVATION_OBJECT_TYPE: &str = "sandbox_credential_reservations";
const RESERVATION_CAS_RETRY_LIMIT: usize = 16;

#[derive(Debug, Default, Deserialize, Serialize)]
struct StoredCredentialReservations {
    reserved_credential_keys: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CredentialReservationSnapshot {
    pub reserved_credential_keys: Vec<String>,
    pub revision: u64,
    pub object_id: Option<String>,
}

#[must_use]
pub(super) fn policy_credential_keys(policy: &SandboxPolicy) -> BTreeSet<String> {
    policy
        .network_policies
        .values()
        .flat_map(|rule| rule.endpoints.iter())
        .flat_map(|endpoint| endpoint.credential_keys.iter())
        .cloned()
        .collect()
}

pub(super) fn reject_credential_keys_outside_sandbox_policy(
    policy: &SandboxPolicy,
    source: &str,
) -> Result<(), Status> {
    let keys = policy_credential_keys(policy);
    if keys.is_empty() {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "credential_keys are supported only in sandbox-scoped base policies; {source} declares: {}",
        keys.into_iter().collect::<Vec<_>>().join(", ")
    )))
}

/// Expand the durable reservation union before committing/acknowledging the
/// policy that introduced the keys. Callers serialize policy mutation paths
/// with `sandbox_sync_guard`; the CAS loop additionally prevents union loss
/// across gateway replicas.
pub(super) async fn persist_policy_credential_reservations(
    store: &Store,
    sandbox_id: &str,
    policy: &SandboxPolicy,
) -> Result<CredentialReservationSnapshot, Status> {
    persist_credential_reservations(store, sandbox_id, policy_credential_keys(policy)).await
}

async fn persist_credential_reservations(
    store: &Store,
    sandbox_id: &str,
    keys: BTreeSet<String>,
) -> Result<CredentialReservationSnapshot, Status> {
    if sandbox_id.is_empty() {
        return Err(Status::internal(
            "cannot persist credential reservations without sandbox ID",
        ));
    }

    for _ in 0..RESERVATION_CAS_RETRY_LIMIT {
        let current = store
            .get_by_name(RESERVATION_OBJECT_TYPE, sandbox_id)
            .await
            .map_err(|error| {
                Status::internal(format!("fetch credential reservations failed: {error}"))
            })?;

        if let Some(record) = current {
            let mut reservations = decode_reservations(&record.payload)?;
            let previous_len = reservations.reserved_credential_keys.len();
            reservations
                .reserved_credential_keys
                .extend(keys.iter().cloned());
            if reservations.reserved_credential_keys.len() == previous_len {
                return Ok(snapshot(reservations, &record.id, record.resource_version));
            }

            let payload = encode_reservations(&reservations)?;
            match store
                .put_if(
                    RESERVATION_OBJECT_TYPE,
                    &record.id,
                    sandbox_id,
                    &payload,
                    None,
                    WriteCondition::MatchResourceVersion(record.resource_version),
                )
                .await
            {
                Ok(result) => {
                    return Ok(snapshot(reservations, &record.id, result.resource_version));
                }
                Err(PersistenceError::Conflict { .. }) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(error) => {
                    return Err(Status::internal(format!(
                        "persist credential reservations failed: {error}"
                    )));
                }
            }
        }

        if keys.is_empty() {
            return Ok(CredentialReservationSnapshot::default());
        }

        let reservations = StoredCredentialReservations {
            reserved_credential_keys: keys.clone(),
        };
        let payload = encode_reservations(&reservations)?;
        let reservation_id = uuid::Uuid::new_v4().to_string();
        match store
            .put_if(
                RESERVATION_OBJECT_TYPE,
                &reservation_id,
                sandbox_id,
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            Ok(result) => {
                return Ok(snapshot(
                    reservations,
                    &reservation_id,
                    result.resource_version,
                ));
            }
            Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {
                tokio::task::yield_now().await;
            }
            Err(error) => {
                return Err(Status::internal(format!(
                    "create credential reservations failed: {error}"
                )));
            }
        }
    }

    Err(Status::aborted(
        "credential reservation update conflicted repeatedly; retry the policy mutation",
    ))
}

pub(super) async fn load_credential_reservations(
    store: &Store,
    sandbox_id: &str,
) -> Result<CredentialReservationSnapshot, Status> {
    let Some(record) = store
        .get_by_name(RESERVATION_OBJECT_TYPE, sandbox_id)
        .await
        .map_err(|error| {
            Status::internal(format!("fetch credential reservations failed: {error}"))
        })?
    else {
        return Ok(CredentialReservationSnapshot::default());
    };
    Ok(snapshot(
        decode_reservations(&record.payload)?,
        &record.id,
        record.resource_version,
    ))
}

/// Best-effort cleanup after the immutable sandbox ID has been deleted. A
/// cleanup failure is fail-closed: the orphaned reservation can only reserve
/// extra names and cannot affect a newly-created sandbox with a different ID.
pub(super) async fn delete_credential_reservations(
    store: &Store,
    sandbox_id: &str,
) -> Result<bool, Status> {
    let Some(record) = store
        .get_by_name(RESERVATION_OBJECT_TYPE, sandbox_id)
        .await
        .map_err(|error| {
            Status::internal(format!(
                "fetch credential reservations for cleanup failed: {error}"
            ))
        })?
    else {
        return Ok(false);
    };
    store
        .delete_if(RESERVATION_OBJECT_TYPE, &record.id, record.resource_version)
        .await
        .map_err(|error| {
            Status::internal(format!("delete credential reservations failed: {error}"))
        })
}

fn snapshot(
    reservations: StoredCredentialReservations,
    object_id: &str,
    revision: u64,
) -> CredentialReservationSnapshot {
    CredentialReservationSnapshot {
        reserved_credential_keys: reservations.reserved_credential_keys.into_iter().collect(),
        revision,
        object_id: Some(object_id.to_string()),
    }
}

fn encode_reservations(reservations: &StoredCredentialReservations) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(reservations).map_err(|error| {
        Status::internal(format!("encode credential reservations failed: {error}"))
    })
}

fn decode_reservations(payload: &[u8]) -> Result<StoredCredentialReservations, Status> {
    serde_json::from_slice(payload).map_err(|error| {
        Status::internal(format!("decode credential reservations failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::test_store;
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};
    use std::collections::HashMap;

    fn policy_with_key(rule_name: &str, key: &str) -> SandboxPolicy {
        SandboxPolicy {
            network_policies: HashMap::from([(
                rule_name.to_string(),
                NetworkPolicyRule {
                    endpoints: vec![NetworkEndpoint {
                        credential_keys: vec![key.to_string()],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn reservations_are_monotonic_across_policy_removal() {
        let store = test_store().await;
        let first = persist_policy_credential_reservations(
            &store,
            "sandbox-1",
            &policy_with_key("mcp", "MCP_TOKEN"),
        )
        .await
        .unwrap();
        let after_removal =
            persist_policy_credential_reservations(&store, "sandbox-1", &SandboxPolicy::default())
                .await
                .unwrap();

        assert_eq!(first.reserved_credential_keys, vec!["MCP_TOKEN"]);
        assert_eq!(after_removal.reserved_credential_keys, vec!["MCP_TOKEN"]);
        assert_eq!(after_removal.revision, first.revision);
    }

    #[tokio::test]
    async fn concurrent_reservation_commits_do_not_lose_union_members() {
        let store = test_store().await;
        let left_store = store.clone();
        let right_store = store.clone();
        let (left, right) = tokio::join!(
            async move {
                persist_policy_credential_reservations(
                    &left_store,
                    "sandbox-1",
                    &policy_with_key("left", "LEFT_TOKEN"),
                )
                .await
            },
            async move {
                persist_policy_credential_reservations(
                    &right_store,
                    "sandbox-1",
                    &policy_with_key("right", "RIGHT_TOKEN"),
                )
                .await
            }
        );
        left.unwrap();
        right.unwrap();

        let persisted = load_credential_reservations(&store, "sandbox-1")
            .await
            .unwrap();
        assert_eq!(
            persisted.reserved_credential_keys,
            vec!["LEFT_TOKEN", "RIGHT_TOKEN"]
        );
        assert!(persisted.revision >= 1);
    }
}
