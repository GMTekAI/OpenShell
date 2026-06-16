---
authors:
  - "@anewberry"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/1919
---

# RFC 0006 - Gateway Interceptors

## Summary

This RFC proposes a first-class Gateway Interceptors system for OpenShell.
Interceptors let operators and external integrators customize gateway API
behavior without forking the gateway or adding special cases to compute
drivers.

Interceptors and drivers serve different extension needs. Interceptors add business logic
around gateway operations. Drivers replace or provide implementation for
platform functionality, such as how sandboxes are provisioned on Docker,
Kubernetes, or VMs.

Gateway Interceptors is the umbrella name for gateway extension points. This
RFC defines one interceptor role:

- **Operation interceptors** observe, modify, validate, reject, or audit gateway
  operations at well-defined phases.

Future RFCs may define event-driven or workflow interceptors under the same
umbrella, but they are out of scope for this first implementation.

Compute drivers continue to own compute-platform provisioning. Interceptors own
gateway-level policy for resource writes: tenancy, quotas, naming, policy
authority, and driver configuration restrictions.

The gateway database remains the system of record. External systems integrate
by writing through existing OpenShell APIs that persist into the gateway DB.
Gateway runtime paths read gateway-owned state; they do not call external
systems during lookup.

## Motivation

OpenShell already has several centralized control-plane paths where the gateway
has enough context to enforce deployment-specific policy:

- Sandbox creation validates requests, defaults images, validates policy
  safety, persists a sandbox object, and provisions through the selected driver.
- Policy and runtime settings are resolved through gateway APIs before they are
  delivered to sandbox supervisors.
- Provider profiles and provider records are stored and resolved by the
  gateway.
- Driver-specific `SandboxTemplate.driver_config` is selected by the gateway
  before the translated `DriverSandbox` reaches the compute driver.

These are the right places for operator-specific control, but today those
controls must be implemented directly in OpenShell code. That does not scale
for organizational requirements such as:

- Sync policies and providers from an external source by writing them through
  existing provider, provider profile, and config APIs.
- Enforce one system-wide sandbox policy and reject custom sandbox policies.
- Verify policy writes against an external authority before accepting them.
- Restrict driver configuration payloads to an approved schema or fixed value.
- Limit each user to a maximum number of running sandboxes.
- Require sandbox names to follow an organization prefix, such as `nvidia-`.

These examples are gateway policy, not compute-driver behavior. A compute
driver can validate whether a pod, container, or VM can be provisioned. It
should not own tenant quotas, global policy authority, provider resource
management, or naming conventions.

## Non-goals

- Replacing compute drivers or adding a second compute provisioning interface.
- Letting interceptors bypass gateway authentication, authorization, policy
  safety validation, or driver schema validation.
- Moving sandbox runtime enforcement out of the sandbox supervisor and proxy.
- Replacing the gateway database as the system of record.

## Proposal

Add a gateway interceptor framework with explicit phases, resource selectors,
deterministic ordering, bounded execution, audit logging, and conservative
failure behavior.

Interceptors do not replace gateway functionality. They add governance and
business logic around resource operations: defaulting, validation, rejection,
and audit. Replacing how core functionality is implemented remains the role of
drivers and other provider-style interfaces.

The design keeps three boundaries intact:

- The gateway database remains the system of record for gateway-owned state.
- Existing gateway and driver validation still run after interceptor
  modification.
- External systems integrate through writes to OpenShell APIs, not live lookup
  calls on runtime paths.

### Operation interceptors

An operation interceptor runs during a gateway operation, such as creating a
sandbox, importing provider profiles, updating policy, or translating a
sandbox request into driver-facing configuration. It may modify a request or
object only in modification phases. It may reject in validation phases. It may
attach warnings and audit annotations in all phases.

Interceptor services expose one or more bindings. A binding is a
service-declared rule that maps the service to phases, resources, operations,
and selectors. The gateway uses bindings to decide when to call the service.

Operation interceptors should work for all gateway operations, not a
hand-maintained subset. Each operation exposes stable interceptor metadata:

- `resource`: the logical resource being operated on, such as a sandbox,
  provider, provider profile, policy/config object, or internal driver-facing
  sandbox request.
- `operation`: the action being performed, such as create, update, delete,
  attach, detach, import, merge, validate, or another domain operation.

The gateway should derive this metadata from the operation being handled rather
than checking it against a fixed allowlist. New gateway operations should enter
the interceptor pipeline by default when they are added.

This lets OpenShell add deployment-specific business logic around the resource
operations it already supports while keeping runtime reads local and
deterministic.

### Gateway state

External systems should not participate in live gateway lookup paths. Instead,
they run controllers or sync jobs that write desired state through existing
OpenShell APIs.

Examples of existing DB-backed state include:

| State | Existing API surface |
|---|---|
| Sandboxes | `CreateSandbox`, `DeleteSandbox`, sandbox provider attach/detach |
| Providers | `CreateProvider`, `UpdateProvider`, `DeleteProvider` |
| Provider profiles | `ImportProviderProfiles`, `DeleteProviderProfile` |
| Sandbox policy and settings | `UpdateConfig`, policy history/status APIs |
| Gateway-global config | `UpdateConfig --global`, gateway settings APIs |

Gateway runtime paths read this state from the gateway store. If an external
catalog or controller is unavailable, the gateway continues using the last
accepted state already persisted in the DB.

External systems integrate by reconciling desired state through existing
OpenShell APIs. The gateway validates and persists those writes, then runtime
paths read the persisted state.

```mermaid
flowchart LR
    External[External catalog/controller] --> API[Existing OpenShell API]
    API --> Interceptors[Operation interceptors]
    Interceptors --> Validate[OpenShell validation]
    Validate --> Store[Gateway DB]
    Store --> Runtime[Gateway runtime reads]
```

Provider profile sync should use the existing provider profile import API.
Provider sync should use the existing provider create/update APIs.

Policy sync should use the existing global and sandbox-scoped config APIs.
Managed deployments that want an authoritative global policy can set the global
policy through `UpdateConfig --global` and use operation interceptors to reject
sandbox-scoped policy changes.

Ownership and provenance should use existing metadata surfaces where available,
such as labels on objects and config fields on provider records. The gateway DB
record is still authoritative; provenance explains how the current desired
state arrived.

This RFC does not introduce new gateway resource kinds for quotas, name
policies, policy bundles, or driver config policy. Those concerns can be
enforced by interceptor services and normal gateway configuration. If
OpenShell later needs first-class resources for them, that should be a separate
RFC.

### Operation phases

Operation phases are ordered. Later phases see the result of earlier phases.

| Phase | Modification allowed | Purpose |
|---|---:|---|
| `pre_request` | yes | Normalize or reject the raw API request after auth and basic size limits. |
| `modify_object` | yes | Apply defaults to the gateway object after standard request parsing. |
| `validate_object` | no | Enforce object-level policy before persistence. |
| `validate_driver` | no | Enforce driver-facing policy after translation to `DriverSandbox`. |
| `post_commit` | no | Emit audit or notify external systems after successful persistence or provisioning. |

For `CreateSandbox`, the phases fit into the existing gateway flow like this:

```text
authenticate request
validate raw field sizes and labels
pre_request interceptors
load gateway-owned providers, policy, and settings
gateway defaulting from stored state
modify_object interceptors
gateway invariant validation
validate_object interceptors
translate to DriverSandbox
validate_driver interceptors
compute driver validation
persist sandbox
driver create
post_commit interceptors
```

Gateway invariants run after modification so interceptors cannot leave invalid
objects in the system. Driver validation still runs after interceptors so
drivers remain the authority for driver-owned schemas.

### Interceptor request contract

The interceptor request should be stable and resource-oriented, not tied to Rust
handler internals.

```proto
message InterceptorReview {
  string api_version = 1;
  string interceptor_name = 2;
  string binding_id = 3;
  string phase = 4;
  string resource = 5;
  string operation = 6;

  InterceptorPrincipal principal = 7;
  InterceptorRequestContext context = 8;

  google.protobuf.Struct object = 9;
  google.protobuf.Struct old_object = 10;
  google.protobuf.Struct request = 11;
}

message InterceptorPrincipal {
  string kind = 1; // user, service, sandbox
  string subject = 2;
  repeated string groups = 3;
}

message InterceptorRequestContext {
  string request_id = 1;
  string gateway_replica_id = 2;
  string compute_driver = 3;
  bool dry_run = 4;
  map<string, string> labels = 5;
}
```

The interceptor response returns an allow/deny decision, optional patches, and
diagnostic metadata for operation interceptors.

```proto
message InterceptorDecision {
  bool allowed = 1;
  string reason = 2;
  string status_code = 3;
  repeated JsonPatch patches = 4;
  repeated string warnings = 5;
  map<string, string> audit_annotations = 6;
}
```

Only modification phases accept patches. A validation interceptor that returns
patches is a configuration error.

The `binding_id` is owned by the interceptor service. It identifies the
service-declared binding that selected the review.

### Interceptor endpoints

The framework supports one service protocol with two transports. The gateway
detects the transport from the interceptor endpoint URI:

- `grpc://host:port` connects to a plaintext gRPC interceptor service over TCP.
- `grpcs://host:port` connects to a TLS-protected gRPC interceptor service over TCP.
- `unix:///path/to/socket` connects to a gRPC interceptor service over a Unix domain
  socket.

Both transports use the same protobuf service contract. Unix domain sockets are
the preferred local deployment shape because they avoid exposing a network
listener and can rely on filesystem permissions. TCP is for interceptors that run as
separate services or outside the gateway host.

### Selection and ordering

Selection should be oriented around interceptor services, not individual
phase/resource routes. Operators should normally configure a small number of
interceptor services and service-specific settings. The service tells the
gateway which operation bindings it supports.

A configured `[[interceptors]]` entry represents one interceptor service
instance. During gateway startup or config reload, the gateway calls a
`Describe` RPC on the service. The response describes the service's default
bindings:

```proto
message InterceptorManifest {
  string api_version = 1;
  repeated InterceptorBinding bindings = 2;
}

message InterceptorBinding {
  string id = 1;
  repeated string phases = 2;
  repeated string resources = 3;
  repeated string operations = 4;
  int32 order = 5;
  bool modifies = 6;
  string default_failure_policy = 7;
  InterceptorSelector selector = 8;
}

message InterceptorSelector {
  repeated string principal_kinds = 1;
  repeated string principal_groups = 2;
  map<string, string> labels = 3;
  repeated string compute_drivers = 4;
}
```

By default, the gateway enables the bindings returned by the service manifest.
Operators can configure the service once, then optionally override specific
bindings when they need to disable, narrow, or reorder behavior. Overrides
should only narrow service-declared selectors unless a future RFC explicitly
allows expansion.

Empty selector fields match all values. For example, a binding with no
`compute_drivers` selector can run for all drivers, while a gateway override can
narrow it to only `kubernetes`.

Example:

```toml
[[interceptors]]
name = "org-controls"
order = 100
failure_policy = "fail_closed"
endpoint = "unix:///run/openshell/interceptors/org-controls.sock"
timeout = "500ms"

[interceptors.config]
sandbox_name_prefix = "nvidia-"
generated_sandbox_names_only = true
max_running_sandboxes_per_user = 10
system_policy_authority = true
policy_authority_endpoint = "grpcs://policy-control.example.com:8443"

[interceptors.config.driver_config.kubernetes.required_payload]
runtimeClassName = "nvidia"

[[interceptors.overrides]]
binding = "provider-profile-governance"
enabled = false

[[interceptors.overrides]]
binding = "driver-config-validation"
failure_policy = "fail_closed"
match = { compute_drivers = ["kubernetes"] }

[[interceptors.overrides]]
binding = "policy-authority"
order = 90
match = { operations = ["update", "merge", "delete"] }
```

The service manifest keeps common configuration terse. Operators do not need to
know that sandbox prefix behavior runs at `modify_object` while driver config
behavior runs at `validate_driver`; the service exposes those bindings.

The gateway builds an execution plan from enabled bindings. Selection evaluates
the service-declared resource, operation, phase, principal, label, and driver
selectors, then applies gateway-configured narrowing overrides.

Interceptors run in fixed phase order. Within a phase, matching bindings run by
this deterministic ordering:

1. configured interceptor service `order`.
2. service-declared binding `order`, after gateway overrides.
3. interceptor service name.
4. binding ID.

The gateway rejects interceptor configuration that creates ambiguous
modification order for the same field if that can be detected statically.

### Failure policy

Each binding has an effective failure policy. The gateway starts with the
service default, applies the interceptor service-level gateway config, then
applies any binding override.

| Failure policy | Behavior |
|---|---|
| `fail_closed` | Interceptor timeout or service error rejects the API operation. |
| `fail_open` | Interceptor timeout or service error permits the operation. The gateway emits warnings and audit logs. |
| `ignore` | Interceptor errors are logged only. Valid only for `post_commit`. |

Defaults:

- Modifying and validating bindings default to `fail_closed`.
- `post_commit` bindings default to `ignore`.

Every interceptor service has a timeout and response size limit. Operation
interceptor bindings also have a maximum patch count.

### Gateway info surface

The first version should not add a dedicated interceptor management API or CLI.
Interceptor configuration remains gateway-local configuration.

The existing gateway info command may expose a read-only summary of configured
interceptor services, enabled bindings, effective failure policies, and last
observed health. That is sufficient for operational visibility in this RFC.

### Observability and audit

Every interceptor decision should emit structured gateway logs with:

- interceptor name.
- binding ID.
- phase.
- resource and operation.
- principal subject.
- decision.
- reason.
- latency.
- failure policy.
- patch count.
- audit annotations.

Security-relevant denials should be emitted as OCSF detection findings or
configuration/security events, depending on the event class. Non-security
operational failures can use plain tracing.

### Security model

Interceptor services run outside the gateway trust boundary. The gateway must
continue to enforce first-party invariants after interceptor modification.

Rules:

- Interceptors receive only the fields needed for their phase.
- `grpcs://` endpoints use TLS and should be required for remote interceptor services.
- `grpc://` endpoints are plaintext and should be limited to loopback or
  explicitly trusted local networks.
- UDS interceptor services rely on filesystem permissions and should be owned by the
  gateway operator.
- Interceptor service responses are bounded by timeout and body size.
  Operation interceptor patches are also bounded by patch count.
- Interceptor services cannot replace built-in validation. Imported profiles and
  policies are validated before use.

### Worked examples

See [policy-governance-example.md](policy-governance-example.md) for a
non-normative example of an organization policy interceptor service with
multiple service-declared bindings and gateway-side overrides.

## Implementation plan

1. Add a `crates/openshell-interceptors` crate with shared interceptor
   manifest, request/response, selector matching, ordering, failure policy
   handling, patch application, and test helpers.
2. Add interceptor configuration parsing to gateway config and validate it at startup.
3. Implement gRPC interceptor clients that derive TCP or Unix domain socket
   transport from the configured endpoint URI and call `Describe` during
   startup or config reload.
4. Build an execution plan from service manifests plus gateway-configured
   overrides.
5. Wire interceptor execution into the gateway operation pipeline so all
   gateway operations can pass through `pre_request`, `modify_object`,
   `validate_object`, `validate_driver`, and `post_commit` where applicable.
6. Add example service bindings for the policy governance workflows described
   in [policy-governance-example.md](policy-governance-example.md).
7. Audit existing gateway operations and route each resource-affecting path
   through the shared interceptor pipeline.
8. Add interceptor decision audit logging and metrics.
9. Document how external controllers should reconcile providers, provider
   profiles, global policy, and sandbox policy through existing APIs.
10. Add read-only interceptor visibility to the existing gateway info command.
11. Document gateway interceptor configuration, endpoint requirements, failure
    modes, and security guidance.

## Risks

- Interceptors can make request behavior harder to reason about if ordering
  and audit are weak.
- Synchronous gRPC interceptor services can become availability dependencies for the
  gateway.
- Modifying interceptors can hide user intent if they silently rewrite user-supplied
  values.
- Ownership can become confusing when external controllers and humans both edit
  the same provider profile, provider, or policy through existing APIs.
- Quota interceptors need a stronger consistency design before they are safe in HA
  deployments.

Mitigations:

- Keep interceptors disabled by default.
- Make ordering deterministic and visible.
- Default modifying and validating interceptors to `fail_closed`.
- Run first-party invariant validation after modification.
- Make HA-unsafe interceptors declare their scope explicitly.

## Alternatives

### Add more gateway config fields

OpenShell could add first-party config fields for each requirement, such as
`sandbox_name_prefix`, `max_sandboxes_per_user`, and
`allowed_driver_config_keys`.

This is simple for known cases but does not scale to organization-specific
policy or external sources. It also keeps growing the gateway config schema for
controls that are not core OpenShell semantics.

### Put this in compute drivers

Drivers already validate driver-owned config. They could also reject names,
quotas, and policy choices.

This mixes responsibilities. Drivers should own compute-platform feasibility.
The gateway should own API behavior, tenancy, policy authority, and provider
state. Interceptors are appropriate for additional business logic around gateway
operations; drivers are appropriate when OpenShell needs a different
implementation of compute functionality.

### Use HTTP webhooks

OpenShell could model interceptors as HTTP webhooks with JSON request and response
payloads.

This is familiar to Kubernetes users, but OpenShell already uses protobuf and
gRPC heavily. A protobuf gRPC contract avoids a second wire format for gateway
extension points, works over Unix domain sockets for local integrations, and
matches the gateway's existing service boundaries.
