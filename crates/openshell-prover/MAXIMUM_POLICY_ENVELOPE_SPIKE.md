<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Maximum Policy Envelope Spike

This spike tests whether OpenShell can compare a candidate policy against a
security-approved maximum policy and reject any candidate that allows more than
the maximum.

Core check:

```text
exists x:
  candidate_allows(x)
  AND NOT maximum_allows(x)
```

Rust normalizes schema-level OpenShell policy semantics, such as access presets
and unsupported field detection. Z3 owns the action variables (`binary`, `host`,
`port`, `protocol`, `method`, and `path`) and checks whether any symbolic action
is allowed by the candidate but not by the maximum. Host, path, and binary globs
compile to Z3 regular-expression constraints. If the solver finds such an `x`,
the candidate exceeds the maximum. If no such `x` exists, the candidate is within
the modeled maximum. If either policy uses a surface the spike does not model
yet, the check fails closed as `Unsupported`.

## Demo 1: Narrow Candidate Within Maximum

Maximum:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*
    binaries:
      - path: /usr/bin/gh
```

Candidate:

```yaml
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
    binaries:
      - path: /usr/bin/gh
```

Result:

```text
WithinMax
```

Why: the candidate narrows the approved path from one issue path glob to one
specific issue.

## Demo 2: Broad Path Proposal Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/OpenShell/issues/*
```

Candidate:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Result:

```text
ExceedsMax {
  binary: "/usr/bin/gh",
  host: "api.github.com",
  port: 443,
  protocol: "rest",
  method: "GET",
  path: "/repos/NVIDIA/",
  reason: "candidate allows an action outside the maximum policy"
}
```

Why: the candidate allows requests outside the approved issue path. The
counterexample is a concrete model selected by Z3: a request the broader
candidate would allow but the maximum would not.

## Demo 3: Method Escalation Exceeds Maximum

Maximum:

```yaml
rules:
  - allow:
      method: GET
      path: /repos/NVIDIA/**
```

Candidate:

```yaml
rules:
  - allow:
      method: POST
      path: /repos/NVIDIA/OpenShell/issues
```

Result:

```text
ExceedsMax {
  method: "POST",
  ...
}
```

Why: the candidate adds a mutating HTTP method outside the maximum's approved
read-only method.

## Demo 4: Host, Binary, and Port Broadening

These candidate changes all exceed a narrower maximum:

```text
host: api.github.com       -> *.github.com
binary: /usr/bin/gh        -> /usr/bin/*
port: 443                  -> [443, 8443]
L7 REST maximum            -> L4-only candidate
```

Why: each change creates at least one action that the maximum does not allow.

## Demo 5: Unsupported Surfaces Fail Closed

Maximum:

```yaml
access: full
deny_rules:
  - method: POST
    path: /admin/**
```

Result:

```text
Unsupported {
  reason: "maximum policy rule 'github' uses deny_rules, which maximum containment does not model yet"
}
```

Why: deny rules change containment semantics. Until the prover models allow plus
deny precedence, the check must not approve these cases.

Other surfaces currently fail closed:

```text
query constraints
GraphQL operation and field constraints
MCP tool/resource constraints
CIDR-only allowed_ips
endpoint path scoping
```

## Narrowness Companion

The maximum-policy check answers whether a candidate stays under a
security-approved ceiling. That is the immediate enterprise gate. The related
narrowness question is different:

```text
How much broader is this candidate than the current policy?
```

A first useful shape is to reuse the same symbolic model and score the proposed
delta:

```text
delta = candidate_allows(x) AND NOT current_allows(x)
score(delta) <= budget
```

This could support:

- per-update budgets, such as "one new REST method" or "one new concrete path";
- total sandbox budgets, such as "no more than N endpoint families";
- hard caps, such as rejecting `**` unless the maximum explicitly grants it;
- reviewer-facing explanations that identify why a change is too broad.

This spike should not over-design the product surface yet. The useful next proof
is a small set of tests showing whether Z3 can produce and classify policy
deltas well enough to enforce simple budgets.

## Current Test Command

```shell
mise exec -- cargo test -p openshell-prover
```

Maximal-policy tests include:

```text
envelope::tests::exact_rest_rule_is_within_maximum
envelope::tests::broader_rest_path_exceeds_maximum
envelope::tests::method_escalation_exceeds_maximum
envelope::tests::host_wildcard_broadening_exceeds_maximum
envelope::tests::binary_wildcard_broadening_exceeds_maximum
envelope::tests::port_broadening_exceeds_maximum
envelope::tests::l4_candidate_exceeds_l7_maximum
envelope::tests::maximum_wildcards_cover_exact_candidate
envelope::tests::deny_rules_are_unsupported_until_modeled
envelope::tests::query_graphql_cidr_and_mcp_surfaces_are_unsupported
```

## Readout

This validates the product shape for REST/path/binary/host/port maximum-policy
envelopes with a symbolic Z3 counterexample query. The next research step on
this branch is a narrowness budget proof over policy deltas. Deny rules, MCP,
GraphQL, query constraints, and CIDR can land as follow-on modeled surfaces once
the containment and delta mechanics are proven useful.
