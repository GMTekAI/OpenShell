# Policy Governance Example

This companion note is non-normative. It shows how one organization policy
interceptor service could expose several bindings through its manifest, so a
gateway operator can configure one service and selectively override behavior.

The service is not a special gateway integration. It uses the same
gRPC-over-TCP or gRPC-over-UDS contract available to external users.

## Example Service Bindings

### System Policy Authority

Reject sandbox-scoped policy creation, update, merge, or delete when an
operator-configured gateway policy is authoritative. Optionally inject the
default policy into sandbox creation when no policy is supplied.

This complements the existing global policy behavior. Global policy override
controls effective sandbox config; this interceptor service makes custom policy
submission fail at the API boundary instead of being silently overridden later.

### External Policy Authority Verifier

Validate global or sandbox-scoped policy writes against an external authority
before the gateway persists them. The external authority might verify a policy
bundle signature, check that a submitted policy was approved by an internal
control plane, or compare policy metadata against an organization-owned source.

This is a write-time validation path. Accepted policy state is still persisted
in the gateway DB and runtime paths continue to read gateway-owned state. If
the external authority is unavailable, the configured failure policy determines
whether the write is rejected or allowed with audit warnings.

### Driver Config Validator

Validate `SandboxTemplate.driver_config` before it reaches a driver. This can
enforce allowed keys, exact payloads, forbidden annotations, resource ceilings,
or driver-specific profiles.

Example:

```yaml
driver: kubernetes
allowed_keys:
  - nodeSelector
  - tolerations
required_payload:
  runtimeClassName: nvidia
```

### User Sandbox Quota

Reject `CreateSandbox` when a principal already has too many active sandboxes.
The initial version may use the existing store list path for single-replica
deployments. A later HA-safe version should use a quota lease or counter with
database compare-and-swap or a transaction.

The rejection code should be `resource_exhausted`.

### Sandbox Name Prefix

Require sandbox names to start with a configured prefix. Generated names may be
modified. User-supplied names should be rejected rather than silently changed.

Example:

```text
generated: bright-lake -> nvidia-bright-lake
supplied: demo -> reject, expected prefix nvidia-
```
