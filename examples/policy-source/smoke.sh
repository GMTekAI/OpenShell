#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET_DIR="${REPO_ROOT}/target/debug"
TMP_PARENT="${OPENSHELL_POLICY_SOURCE_TMPDIR:-/tmp}"
TMP_DIR="$(mktemp -d "${TMP_PARENT}/openshell-policy-source.XXXXXX")"
SOCKET="${TMP_DIR}/policy-source.sock"
SERVER_LOG="${TMP_DIR}/server.log"
GATEWAY_LOG="${TMP_DIR}/gateway.log"
GATEWAY_CONFIG="${TMP_DIR}/gateway.toml"
GATEWAY_DB="${TMP_DIR}/gateway.db"
if [[ -n "${OPENSHELL_POLICY_SOURCE_GATEWAY_PORT:-}" ]]; then
  GATEWAY_PORT="${OPENSHELL_POLICY_SOURCE_GATEWAY_PORT}"
else
  GATEWAY_PORT="$((20000 + RANDOM % 20000))"
fi
if [[ -n "${OPENSHELL_POLICY_SOURCE_GATEWAY_HEALTH_PORT:-}" ]]; then
  GATEWAY_HEALTH_PORT="${OPENSHELL_POLICY_SOURCE_GATEWAY_HEALTH_PORT}"
else
  GATEWAY_HEALTH_PORT="$((GATEWAY_PORT + 1))"
fi
GATEWAY_ENDPOINT="http://127.0.0.1:${GATEWAY_PORT}"
SERVER_PID=""
GATEWAY_PID=""
CASE_INDEX=0
FAILED=0
LAST_LOG=""

cleanup() {
  if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    kill "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${TMP_DIR}/bundle/policies" "${TMP_DIR}/bundle/providers"
cp "${SCRIPT_DIR}/bundle/policies/default.yaml" "${TMP_DIR}/bundle/policies/default.yaml"
cp "${SCRIPT_DIR}/bundle/providers/gitlab.yaml" "${TMP_DIR}/bundle/providers/gitlab.yaml"
cp "${SCRIPT_DIR}/bundle/providers/github.yaml" "${TMP_DIR}/bundle/providers/github.yaml"

echo "Building policy source example binaries"
RUSTC_WRAPPER= cargo build \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p openshell-policy-source-example \
  --bin policy-source-server \
  --bin policy-source-check \
  --bin policy-source-gateway-check

echo "Building gateway"
RUSTC_WRAPPER= cargo build \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p openshell-server \
  --features bundled-z3 \
  --bin openshell-gateway

echo "Starting policy source server on ${SOCKET}"
"${TARGET_DIR}/policy-source-server" --socket "${SOCKET}" --root "${TMP_DIR}/bundle" \
  >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

for _ in {1..50}; do
  if [[ -S "${SOCKET}" ]]; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "policy source server exited early" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
  fi
  sleep 0.1
done

if [[ ! -S "${SOCKET}" ]]; then
  echo "policy source socket was not created: ${SOCKET}" >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi

run_command() {
  CASE_INDEX=$((CASE_INDEX + 1))
  LAST_LOG="${TMP_DIR}/case-${CASE_INDEX}.log"
  "$@" >"${LAST_LOG}" 2>&1
}

expect_success() {
  run_command "$@"
}

expect_failure() {
  if run_command "$@"; then
    echo "unexpected success" >>"${LAST_LOG}"
    return 1
  fi
  return 0
}

scenario() {
  local name="$1"
  shift

  printf "%s: " "${name}"
  if "$@"; then
    echo "PASS"
  else
    echo "FAIL"
    FAILED=1
    if [[ -n "${LAST_LOG}" && -f "${LAST_LOG}" ]]; then
      sed 's/^/  /' "${LAST_LOG}" >&2
    fi
  fi
}

detect_driver() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "docker"
    return 0
  fi
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    echo "podman"
    return 0
  fi
  return 1
}

gateway_check() {
  "${TARGET_DIR}/policy-source-gateway-check" --endpoint "${GATEWAY_ENDPOINT}" --case "$1"
}

create_gateway_config() {
  local driver="$1"
  cat >"${GATEWAY_CONFIG}" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:${GATEWAY_PORT}"
health_bind_address = "127.0.0.1:${GATEWAY_HEALTH_PORT}"
compute_drivers = ["${driver}"]
disable_tls = true
log_level = "info"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.policies]
location = "grpc+unix://${SOCKET}"
global_policy = "default"
enforcement = "strict"
EOF
}

wait_for_gateway() {
  for _ in {1..100}; do
    if curl -fsS "http://127.0.0.1:${GATEWAY_HEALTH_PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
      echo "gateway exited early" >&2
      cat "${GATEWAY_LOG}" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "gateway did not become healthy" >&2
  cat "${GATEWAY_LOG}" >&2
  return 1
}

start_gateway() {
  local driver
  driver="$(detect_driver)" || {
    echo "no running Docker or Podman driver found" >&2
    return 1
  }
  create_gateway_config "${driver}"
  echo "Starting gateway on ${GATEWAY_ENDPOINT} with ${driver}"
  "${TARGET_DIR}/openshell-gateway" \
    --config "${GATEWAY_CONFIG}" \
    --db-url "sqlite://${GATEWAY_DB}" \
    >"${GATEWAY_LOG}" 2>&1 &
  GATEWAY_PID="$!"
  wait_for_gateway
}

create_base_sandbox() {
  gateway_check create-base-sandbox
}

attach_known_provider() {
  if [[ "${SANDBOX_CREATED:-0}" != "1" ]]; then
    LAST_LOG="${TMP_DIR}/case-sandbox-setup.log"
    echo "sandbox setup failed; cannot test provider attach" >"${LAST_LOG}"
    return 1
  fi
  expect_success gateway_check attach-known-provider
}

cannot_create_or_attach_new_providers() {
  if [[ "${SANDBOX_CREATED:-0}" != "1" ]]; then
    LAST_LOG="${TMP_DIR}/case-new-provider.log"
    echo "sandbox setup failed; cannot test provider attach" >"${LAST_LOG}"
    return 1
  fi
  expect_success gateway_check new-provider-rejected
}

scenario "policy source serves default policy and github/gitlab providers" \
  expect_success "${TARGET_DIR}/policy-source-check" \
    --socket "${SOCKET}" \
    --expect-policy default \
    --expect-provider gitlab \
    --expect-provider github

if start_gateway; then
  scenario "custom policy on a sandbox is rejected" \
    expect_success gateway_check custom-policy-rejected

  scenario "cannot modify a policy" \
    expect_success gateway_check policy-modification-rejected

  SANDBOX_CREATED=0
  if create_base_sandbox >"${TMP_DIR}/sandbox-create.log" 2>&1; then
    SANDBOX_CREATED=1
  else
    echo "sandbox setup failed" >&2
    sed 's/^/  /' "${TMP_DIR}/sandbox-create.log" >&2
  fi

  scenario "allowed to attach known providers from the bundle" attach_known_provider
  scenario "cannot create or attach new providers" cannot_create_or_attach_new_providers
else
  FAILED=1
  for name in \
    "custom policy on a sandbox is rejected" \
    "cannot modify a policy" \
    "allowed to attach known providers from the bundle" \
    "cannot create or attach new providers"; do
    echo "${name}: FAIL"
  done
fi

if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi
