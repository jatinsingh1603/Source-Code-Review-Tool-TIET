# Docker on demo day

Owning epic: E39 (issue E39-02). The full deployment guide is [`docs/guide/deploy.md`](../guide/deploy.md); the dashboard walk-through is [`DEMO2.md`](DEMO2.md).

## Before the session

```console
$ cp .env.example .env && chmod 600 .env     # admin password, AgentRouter key, vault passphrase
$ docker compose up -d --build
$ docker compose ps                          # "(healthy)"
$ curl -s http://127.0.0.1:8080/api/v1/health
```

Build the image the day before: the first build downloads base images and dependencies and takes a few minutes. After that, `docker compose up -d` starts in seconds and needs no network.

## During the session

| Show | Command |
|------|---------|
| It is one container | `docker compose ps` |
| It runs as non-root with a read-only filesystem | `docker compose exec codekavach id` and `docker inspect codekavach-codekavach-1 --format '{{.HostConfig.ReadonlyRootfs}}'` |
| The engines are inside | `docker compose exec codekavach opengrep --version` and `... bandit --version` |
| The CLI is the same tool | `docker compose exec codekavach codekavach doctor` |
| Nothing needs the network | `docker compose --profile airgapped up -d codekavach-airgapped`, then `docker compose exec codekavach-airgapped codekavach scan /app/fixtures/kavachbank --provider mock` |

## Hand-over

The receiving team needs the repository, Docker and this page. `docker compose down` keeps the data volume; `docker compose down -v` removes it. For a cluster, the Helm chart is in `deploy/helm/codekavach`; for a machine with no network, `make bundle` (see [`docs/guide/install.md`](../guide/install.md#air-gapped-bundle)).
