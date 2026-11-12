# LLM providers

<!-- Written by `uv run python -m codekavach.llm.providers.docgen`; do not edit. -->

Every provider kind CodeKavach knows, the wire format its adapter speaks, and how far it has been verified. Adapters build requests and parse answers only; every request leaves through the egress guard, the ledger and the single transport (invariant I1).

| kind | name | wire format | local | key | structured output | verification |
|------|------|-------------|-------|-----|-------------------|--------------|
| `anthropic` | Anthropic | anthropic-messages | no | yes | tool, prompt | verified offline (request building and recorded envelopes) |
| `azure-openai` | Azure OpenAI | openai-chat | no | yes | json_schema, json_object, prompt | verified offline (request building and recorded envelopes) |
| `bedrock` | AWS Bedrock | bedrock-converse | no | yes | tool, prompt | verified offline (request building and recorded envelopes) |
| `cli-bridge` | Local CLI bridge | subprocess | yes | no | - | no adapter in this build |
| `gemini` | Google Gemini | gemini-generate-content | no | yes | json_schema, prompt | verified offline (request building and recorded envelopes) |
| `litellm` | LiteLLM proxy | openai-chat | no | no | json_schema, json_object, prompt | verified offline (request building and recorded envelopes) |
| `mock` | Mock (offline) | none | yes | no | json_schema | verified offline (request building and recorded envelopes) |
| `ollama` | Ollama (native) | ollama-chat | yes | no | json_schema, prompt | verified offline (request building and recorded envelopes) |
| `openai` | OpenAI | openai-responses | no | yes | json_schema, json_object, prompt | verified against a live endpoint |
| `openai-compatible` | OpenAI-compatible server | openai-chat | no | no | json_schema, json_object, prompt | verified offline (request building and recorded envelopes) |
| `replay` | Replay (recorded) | none | yes | no | json_schema | verified offline (request building and recorded envelopes) |
| `vertex` | Google Vertex AI | gemini-generate-content | no | yes | json_schema, prompt | verified offline (request building and recorded envelopes) |
| `xai` | xAI | openai-chat | no | yes | json_schema, json_object, prompt | verified offline (request building and recorded envelopes) |

## Retention notes

- `anthropic`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `azure-openai`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `bedrock`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `cli-bridge`: Not available in this build.
- `gemini`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `litellm`: Retention depends on where base_url points: local servers keep nothing off the machine, hosted gateways follow their own terms.
- `mock`: Runs on this machine; nothing is retained by a third party.
- `ollama`: Runs on this machine; nothing is retained by a third party.
- `openai`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `openai-compatible`: Retention depends on where base_url points: local servers keep nothing off the machine, hosted gateways follow their own terms.
- `replay`: Runs on this machine; nothing is retained by a third party.
- `vertex`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.
- `xai`: Hosted: payloads leave the machine; check the vendor's data-retention and training terms for your account before use.

## Presets

A provider entry with `preset = "<name>"` takes the preset's endpoint, model, key reference and options; anything set explicitly in the entry wins.

| preset | kind | endpoint | default model | key reference |
|--------|------|----------|---------------|---------------|
| `agentrouter` | `openai` | https://agentrouter.org/v1 | gpt-5.6-sol | env:CODEKAVACH_AGENTROUTER_API_KEY |
| `anthropic` | `anthropic` | https://api.anthropic.com | - | kind default |
| `gemini` | `gemini` | https://generativelanguage.googleapis.com/v1beta | - | kind default |
| `lmstudio` | `openai-compatible` | http://127.0.0.1:1234/v1 | - | kind default |
| `ollama-openai` | `openai-compatible` | http://127.0.0.1:11434/v1 | - | kind default |
| `openai` | `openai` | https://api.openai.com/v1 | - | kind default |
| `openrouter` | `openai-compatible` | https://openrouter.ai/api/v1 | - | env:OPENROUTER_API_KEY |
| `vllm` | `openai-compatible` | http://127.0.0.1:8000/v1 | - | kind default |
| `xai` | `xai` | https://api.x.ai/v1 | - | kind default |

## Built-in providers

These are present without configuration when named with `--provider <id>` (or as `llm.default_provider`) or when their key variable is set. `auto` never selects them.

- `agentrouter`: key in `CODEKAVACH_AGENTROUTER_API_KEY`, or in the file named by `CODEKAVACH_AGENTROUTER_API_KEY_FILE`

## Conformance

`pytest tests/conformance -m conformance` checks every adapter kind offline and replays the responses recorded under `tests/conformance/cassettes/` by `tools/record_conformance.py` (bundled synthetic payload only). `CODEKAVACH_CONFORMANCE_LIVE=1` adds a live probe of the providers named in `CODEKAVACH_CONFORMANCE_PROVIDERS` (default `agentrouter`); it is skipped without a key.
