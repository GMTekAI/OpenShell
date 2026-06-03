# opencode + privacy-preserving image redaction

Run [opencode](https://opencode.ai) inside an OpenShell sandbox where image payloads are kept away from the public inference provider and recovered, on demand, through a private local model.

opencode talks to `inference.local`, which is routed to a host-side OpenAI-compatible **redaction proxy**. The proxy decides per request, from a content policy, whether to let an image through to the public model or to strip it and tell opencode to recover the data via a **local-model MCP server** running on the same host.

```
opencode (sandbox)
  ├── chat ── inference.local ──▶ redaction proxy (host :8000) ──▶ public model (gpt-5.5)
  │                                   │ if content_policy image: redact
  │                                   └─ strips image, injects "use the local_model MCP"
  └── tool ── local_model MCP (host :8001) ──▶ private/local model (e.g. LM Studio :1234)
```

The "demo magic": the proxy reads an OpenShell-style policy file (`policies/content-policy.yaml`) on **every** request. OpenShell itself does not interpret the `content_policy` block (that would need code changes) - only this proxy does. Flip one line and the next image request changes routing, no restart.

## Layout

| Path | What |
|------|------|
| `proxy/` | The redaction proxy + `call_inference` MCP server (a `uv` project). |
| `proxy/Makefile` | Start/stop the proxy and MCP; flip the demo policy. |
| `policies/opencode-policy.yaml` | Sandbox policy you give to OpenShell at create time (includes weather egress for the demo task). |
| `policies/content-policy.yaml` | Copy of the policy **plus** the `content_policy` block the proxy reads. |
| `sandbox/opencode.json` | opencode config: `inference.local` provider + `local_model` MCP. |
| `sandbox/opencode-provision.sh` | Writes the config + workspace inside the sandbox. |
| `sandbox/setup-sandbox.sh` | One command: create sandbox, provision, run web UI, expose it. |

## Prerequisites

- An OpenShell gateway registered and selected: `openshell gateway list` (the active one must be reachable as `host.openshell.internal` from sandboxes - this is the default for the local podman/VM gateway).
- A private/local OpenAI-compatible model for the MCP to call (the example defaults to LM Studio at `http://localhost:1234`).
- An `NVIDIA_API_KEY` for the public upstream (`https://inference-api.nvidia.com`).
- `uv` installed.

## 1. Start the host services

```shell
cd proxy
cp .env.example .env          # then put your NVIDIA_API_KEY in .env
uv sync
make start                    # starts the MCP (:8001) and proxy (:8000)
```

The proxy and MCP bind to `0.0.0.0` so the sandbox can reach them via `host.openshell.internal`.

## 2. One-time gateway wiring (inference.local -> the proxy)

```shell
openshell provider create --name local-proxy --type openai \
  --credential OPENAI_API_KEY=dummy \
  --config OPENAI_BASE_URL=http://host.openshell.internal:8000/v1

openshell inference set --provider local-proxy --model openai/openai/gpt-5.5 --no-verify
```

`--no-verify` because host-side validation cannot resolve `host.openshell.internal`; runtime egress originates inside the sandbox and works.

## 3. Create the opencode sandbox

```shell
cd sandbox
./setup-sandbox.sh
```

This creates the `opencode` sandbox with `policies/opencode-policy.yaml`, writes `opencode.json`, starts `opencode web` on loopback inside the sandbox, and exposes it. Open the printed URL (e.g. `http://opencode--web.openshell.localhost:<gateway-port>/`).

Sanity check from the CLI:

```shell
ssh -F /tmp/opencode-ssh-config openshell-opencode \
  'export HOME=/sandbox; cd /sandbox/workspace; opencode run --model inference-local/openai/openai/gpt-5.5 "say hi"'
```

## 4. Demo: flip the content policy

Default state ships as `redact`. Watch the proxy log while you drive opencode from the web UI:

```shell
cd proxy && make tail-proxy-log
```

- **Allow** (`make demo-allow`): attach an image in opencode and ask about it. The proxy logs `image_redaction_skipped reason=allowed_by_policy` and the image reaches the public model.
- **Redact** (`make demo-redact`): re-send. The proxy logs `image_redaction_applied`, the image is replaced with the `redact_description`, and opencode calls the `local_model` MCP tool to recover the data from the private model. The image never reaches the public model.

`make demo-status` shows the current rule. The proxy re-reads the file per request, so no restart is needed between toggles.

Request/response captures land in `proxy/request-logs/` (gitignored) for inspection.

## Tear down

```shell
cd proxy && make stop
openshell service delete opencode web
openshell sandbox delete opencode
```

## Tests

```shell
cd proxy && make test
```
