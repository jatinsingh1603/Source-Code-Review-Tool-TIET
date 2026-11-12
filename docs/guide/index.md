# CodeKavach

**Privacy-preserving, LLM-assisted secure source code review.** *Kavach* means armour: CodeKavach gets you a standards-based security review of your code from a large language model, while keeping secrets and personal data on your machine and measuring how much of your business logic is disclosed.

## Start here

| I want to... | Read |
|--------------|------|
| Install it and run a first scan | [User guide](user-guide.md) |
| Read a report and sign off | [Auditor guide](auditor-guide.md) |
| Deploy for a team, manage users and policy | [Admin guide](admin-guide.md) |
| Connect AgentRouter, OpenAI, Anthropic or a local model | [Provider guide](providers.md) |
| Understand the privacy approach and its limits | [Whitepaper](whitepaper.md) |
| Measure detection and leakage | [Evaluation guide](evaluation.md) |
| Look up a command | [Command-line reference](../reference/cli.md) |
| Call the API | [REST API](../reference/rest-api.md) |

## Quickstart

```console
$ cp .env.example .env
$ docker compose up -d --build        # then open http://127.0.0.1:8080
```

or, from a checkout, offline:

```console
$ uv sync --all-extras
$ uv run codekavach demo --out demo-out
```
