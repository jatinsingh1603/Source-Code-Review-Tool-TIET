# Provider guide

A provider is the model that reviews the candidate findings. CodeKavach talks to every provider through the same layer: a payload is prepared by the privacy layer, checked by the egress guard, recorded in the ledger and only then sent. A provider never sees a file path, a secret or an original identifier, and which level of preparation applies depends on the provider's trust tier.

List what is available and test one:

```console
$ codekavach providers list
$ codekavach providers test agentrouter
```

In the dashboard: **Providers**, **Run health checks** (each configured provider is tested; one without its key is skipped and shows **Key missing**).

## Local providers (nothing leaves the machine)

| Provider | Use |
|----------|-----|
| `mock` | Canned answers; for demonstrations and checking the pipeline. It has no judgement, so its verdicts say nothing about your code. |
| `replay` | Answers from recorded cassettes (for example `fixtures/kavachbank/cassettes`). Reproducible offline demos and tests. |
| `ollama` | A model served by [Ollama](https://ollama.com) on this machine or in the compose `local-llm` profile. |
| `vllm`, `lmstudio`, `ollama-openai` | Local OpenAI-compatible servers (presets). |

Ollama in compose:

```console
$ docker compose --profile local-llm up -d
$ docker compose exec ollama ollama pull qwen2.5-coder:7b
```

Use model names that really run locally. Tags ending in `-cloud` run on the vendor's servers even though the client talks to a local daemon; the compose profile sets `OLLAMA_NO_CLOUD=1` to refuse them.

Local models mean the lowest disclosure (L0 sends nothing), at the price of weaker reasoning than a frontier model on subtle issues.

## Hosted providers

A hosted provider receives prepared payloads. Check its data-retention and training terms for your account before use; CodeKavach does not paraphrase vendor terms.

| Id | Kind | Key variable | Notes |
|----|------|--------------|-------|
| `agentrouter` | OpenAI Responses API gateway | `CODEKAVACH_AGENTROUTER_API_KEY` | Preset: base URL `https://agentrouter.org/v1`, model `gpt-5.6-sol`, Responses wire format. Used for the project demo. |
| `openai` | OpenAI | `OPENAI_API_KEY` | Chat or Responses API. |
| `anthropic` | Anthropic Messages API | `ANTHROPIC_API_KEY` | |
| `gemini`, `vertex` | Google | `GEMINI_API_KEY` / Vertex credentials | |
| `xai` | xAI | `XAI_API_KEY` | |
| `bedrock` | AWS Bedrock | AWS credentials | |
| `azure-openai` | Azure OpenAI | `AZURE_OPENAI_API_KEY` | For organisations that already contract with Azure. |
| `openrouter` | OpenAI-compatible | `OPENROUTER_API_KEY` | Chat completions. |
| `litellm`, `openai-compatible` | Any gateway | per provider | Point `base_url` at your gateway. |

### Using AgentRouter

AgentRouter is built in; naming it is enough.

```console
$ export CODEKAVACH_AGENTROUTER_API_KEY=...            # or put it in .env for compose
$ codekavach scan ./myproject --provider agentrouter --privacy-level L3 --accept-egress
```

In the dashboard choose `agentrouter` in the scan wizard. The adapter sends the headers the gateway requires and uses structured output so that the verdict is parsed rather than scraped. An unset key makes the provider show as not configured, and a scan with it fails before anything is sent.

### Configuring any provider

In `codekavach.toml` (written by `codekavach init`):

```toml
[llm]
default_provider = "primary"
allow_remote = true

[llm.providers.primary]
kind = "anthropic"
api_key = "env:ANTHROPIC_API_KEY"     # a reference; a plaintext key is refused
model = "claude-sonnet-4-5"          # choose the model you have access to

[llm.providers.internal]
kind = "openai-compatible"
base_url = "https://llm.internal.example/v1"
api_key = "file:/run/secrets/internal_llm_key"
model = "qwen2.5-coder-32b"
```

Key references are `env:NAME`, `file:/path` or `keyring:name`. The configuration loader refuses a plaintext key. Every option is in the [configuration reference](../configuration/reference.md).

## Choosing a provider and a level

| Situation | Suggestion |
|-----------|------------|
| Demonstration, CI smoke test | `mock` or `replay`. |
| Client code that must not leave the network | `ollama` or another local server, level L0 or any. |
| Client code, hosted model allowed | A hosted provider at **L3** or **L4**, with the minimum level enforced by organisation policy. |
| Open-source code you own | Any provider at L1 or L2 is acceptable. |

The detection and leakage evaluations ([Evaluation](evaluation.md)) are how to compare a provider and a level on your own labelled code: `codekavach eval detection --provider NAME`.

## What the test button does

`providers test` and the dashboard **Test** button send a tiny fixed prompt through the same egress path as a scan, to confirm the key, the network path and the model name. It sends no project data. Raw error bodies from a provider are never printed, because some echo parts of the request.
