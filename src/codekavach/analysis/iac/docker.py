# ruff: noqa: SIM102, PLR0912
"""Dockerfile and docker-compose checks."""

import re
from typing import Any, Final

from codekavach.analysis.iac.common import Issue, YMap, load_yaml, truthy, walk
from codekavach.core.models import Confidence, Severity

_SECRET_NAME: Final = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.I
)
_FROM: Final = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
_ENV_PAIR: Final = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(\S.*)")
_PIPE_SHELL: Final = re.compile(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)


def check_dockerfile(text: str) -> list[Issue]:
    """Root user, floating tags, remote ADD, secrets in ENV/ARG and pipe-to-shell installs."""
    issues: list[Issue] = []
    lines = text.splitlines()
    last_from = 0
    last_user: tuple[str, int] | None = None
    stage_names: set[str] = set()
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        keyword = line.split(None, 1)[0].upper()
        if m := _FROM.match(line):
            image = m.group(1)
            last_from = number
            last_user = None
            if image.lower() != "scratch" and image not in stage_names:
                name = image.split("@", 1)[0]
                tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else ""
                if "@sha256:" not in image and tag in {"", "latest"}:
                    issues.append(
                        Issue(
                            "iac.docker.unpinned-base-image",
                            number,
                            Severity.LOW,
                            1104,
                            "Base image uses the floating 'latest' tag or no tag, so builds are "
                            "not reproducible and may pull an unreviewed image.",
                        )
                    )
            if m.group(2):
                stage_names.add(m.group(2))
        elif keyword == "USER":
            parts = line.split(None, 1)
            last_user = (parts[1].strip().split(":")[0] if len(parts) > 1 else "", number)
        elif keyword == "ADD":
            args = [a for a in line.split()[1:] if not a.startswith("--")]
            if args and re.match(r"https?://", args[0], re.I):
                issues.append(
                    Issue(
                        "iac.docker.add-remote-url",
                        number,
                        Severity.MEDIUM,
                        494,
                        "ADD fetches a remote URL with no integrity check; use COPY plus a "
                        "verified download.",
                    )
                )
        elif keyword in {"ENV", "ARG"}:
            body = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            for pair in _env_pairs(body):
                name, value = pair
                if _SECRET_NAME.search(name) and value and not value.startswith("$"):
                    issues.append(
                        Issue(
                            "iac.docker.secret-in-env",
                            number,
                            Severity.HIGH,
                            798,
                            f"{keyword} {name} bakes a credential into the image layers; use "
                            "a build secret or runtime injection.",
                        )
                    )
        elif keyword == "RUN" and _PIPE_SHELL.search(line):
            issues.append(
                Issue(
                    "iac.docker.pipe-to-shell",
                    number,
                    Severity.MEDIUM,
                    494,
                    "RUN pipes a download straight into a shell without integrity verification.",
                    Confidence.MEDIUM,
                )
            )
    if last_from:
        if last_user is None or last_user[0].lower() in {"root", "0", ""}:
            where = last_user[1] if last_user else last_from
            issues.append(
                Issue(
                    "iac.docker.root-user",
                    where,
                    Severity.MEDIUM,
                    250,
                    "The container runs as root (no non-root USER in the final stage).",
                )
            )
    return issues


def _env_pairs(body: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if "=" in body.split(None, 1)[0] if body.split() else False:
        for token in re.findall(r"""[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)""", body):
            name, _, value = token.partition("=")
            pairs.append((name, value.strip("\"'")))
    elif (m := _ENV_PAIR.match(body)) is not None:
        pairs.append((m.group(1), m.group(2).strip().strip("\"'")))
    return pairs


def check_compose(text: str) -> list[Issue]:
    """Privileged containers, host namespaces, docker socket mounts and inline credentials."""
    issues: list[Issue] = []
    for doc in load_yaml(text):
        services = doc.get("services") if isinstance(doc, YMap) else None
        if not isinstance(services, YMap):
            continue
        for name, svc in services.items():
            if not isinstance(svc, YMap):
                continue
            if truthy(svc.get("privileged")):
                issues.append(
                    Issue(
                        "iac.compose.privileged",
                        svc.line_of("privileged"),
                        Severity.HIGH,
                        250,
                        f"Service '{name}' runs privileged, giving it nearly full host access.",
                    )
                )
            if str(svc.get("network_mode", "")).lower() == "host":
                issues.append(
                    Issue(
                        "iac.compose.host-network",
                        svc.line_of("network_mode"),
                        Severity.MEDIUM,
                        668,
                        f"Service '{name}' shares the host network namespace.",
                    )
                )
            if str(svc.get("pid", "")).lower() == "host":
                issues.append(
                    Issue(
                        "iac.compose.host-pid",
                        svc.line_of("pid"),
                        Severity.HIGH,
                        250,
                        f"Service '{name}' shares the host PID namespace.",
                    )
                )
            _compose_volumes(name, svc, issues)
            _compose_env(name, svc, issues)
            caps = svc.get("cap_add")
            if isinstance(caps, list) and any(str(c).upper() in {"SYS_ADMIN", "ALL"} for c in caps):
                issues.append(
                    Issue(
                        "iac.compose.dangerous-capability",
                        svc.line_of("cap_add"),
                        Severity.HIGH,
                        250,
                        f"Service '{name}' adds SYS_ADMIN or ALL capabilities.",
                    )
                )
    return issues


def _compose_volumes(name: str, svc: YMap, issues: list[Issue]) -> None:
    volumes = svc.get("volumes")
    if not isinstance(volumes, list):
        return
    for vol in volumes:
        spec = vol.get("source", "") if isinstance(vol, dict) else str(vol)
        if "docker.sock" in str(spec):
            issues.append(
                Issue(
                    "iac.compose.docker-socket",
                    svc.line_of("volumes"),
                    Severity.HIGH,
                    250,
                    f"Service '{name}' mounts the Docker socket, which is root on the host.",
                )
            )


def _compose_env(name: str, svc: YMap, issues: list[Issue]) -> None:
    env: Any = svc.get("environment")
    pairs: list[tuple[str, str]] = []
    if isinstance(env, dict):
        pairs = [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    elif isinstance(env, list):
        pairs = [tuple(str(e).split("=", 1)) for e in env if "=" in str(e)]  # type: ignore[misc]
    for key, value in pairs:
        if _SECRET_NAME.search(key) and value and not value.startswith("$"):
            issues.append(
                Issue(
                    "iac.compose.secret-in-environment",
                    svc.line_of("environment"),
                    Severity.HIGH,
                    798,
                    f"Service '{name}' sets {key} to a literal in the compose file; use an "
                    "env file or secret store.",
                )
            )


def compose_like(doc_text: str) -> bool:
    """True when ``doc_text`` parses as a compose file (has a services mapping)."""
    return any(
        isinstance(d, YMap) and isinstance(d.get("services"), YMap) for d in load_yaml(doc_text)
    )


__all__ = ["check_compose", "check_dockerfile", "compose_like", "walk"]
