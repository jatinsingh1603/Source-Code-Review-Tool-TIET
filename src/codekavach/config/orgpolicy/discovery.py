"""Finding and trusting organisation policy files (ADR decision D7, E03-28).

Owning epic: E03.

The trust anchor is the location: a policy is read only from fixed system paths
(``paths.system_policy_paths()``) and from the file named by ``CODEKAVACH_ORG_POLICY``, never
from inside the project root. Every discovered policy applies (system first, then the variable),
so setting the variable cannot replace a system policy with a weaker one, and no variable changes
the system path list. Every problem with a configured policy aborts the run (fail closed, I4).

What path pinning defends: the scanned repository and project-level configuration cannot supply
or weaken the policy. What it does not defend: a local administrator, or whoever controls the
process environment. ``CODEKAVACH_ORG_POLICY_SHA256``, set by a pipeline template, narrows the
second case; E03-31 adds detached signatures. On Windows the POSIX owner and mode-bit checks are
skipped; every other check applies.
"""

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from codekavach.config import paths
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue, OrgPolicyError
from codekavach.config.orgpolicy.model import OrgPolicy
from codekavach.config.plaintext import find_plaintext_secrets
from codekavach.config.toml_source import read_toml

ORG_POLICY_ENV = "CODEKAVACH_ORG_POLICY"
ORG_POLICY_SHA256_ENV = "CODEKAVACH_ORG_POLICY_SHA256"


@dataclass(frozen=True, slots=True)
class LoadedOrgPolicy:
    """A validated policy with where it came from."""

    policy: OrgPolicy
    path: Path
    sha256: str
    origin: Literal["system", "env"]
    signature: Literal["not-checked", "valid"] = "not-checked"


def _error(
    code: ConfigErrorCode, path: Path, message: str, hint: str | None = None
) -> OrgPolicyError:
    return OrgPolicyError.single(code, message, source=str(path), hint=hint)


def _as_policy_error(error: ConfigError, path: Path, code: ConfigErrorCode) -> OrgPolicyError:
    return OrgPolicyError(
        [replace(issue, code=code, severity="error", source=str(path)) for issue in error.issues]
    )


def check_policy_file_trust(path: Path, *, project_root: Path) -> None:
    """Refuse a policy inside the project (051) or writable by another local user (052).

    Raises:
        OrgPolicyError: code 051 or 052.
    """
    real = path.resolve()
    if real.is_relative_to(project_root.resolve()):
        raise _error(
            ConfigErrorCode.CK_CFG_051,
            path,
            "organisation policy is located inside the project root",
            "an organisation policy must come from a location the repository cannot write",
        )
    try:
        paths.check_trusted_file(path, what="organisation policy", code=ConfigErrorCode.CK_CFG_052)
    except ConfigError as error:
        raise _as_policy_error(error, path, ConfigErrorCode.CK_CFG_052) from None


def _validation_issues(error: ValidationError, path: Path) -> list[ConfigIssue]:
    issues = []
    for item in error.errors(include_input=False, include_url=False):
        key = ".".join(str(part) for part in item["loc"] if not str(part).startswith("function"))
        message = str(item["msg"]).removeprefix("Value error, ").removeprefix("[CK-CFG-050] ")
        issues.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_050,
                severity="error",
                message=f"invalid organisation policy: {message}",
                key=key or None,
                source=str(path),
            )
        )
    return issues


def _load_one(
    path: Path,
    origin: Literal["system", "env"],
    *,
    project_root: Path,
    today: date,
    pinned_sha256: str | None,
) -> LoadedOrgPolicy:
    if not path.is_file():
        raise _error(ConfigErrorCode.CK_CFG_050, path, "organisation policy file does not exist")
    check_policy_file_trust(path, project_root=project_root)
    try:
        document = read_toml(path)
    except ConfigError as error:
        raise _as_policy_error(error, path, ConfigErrorCode.CK_CFG_050) from None
    if pinned_sha256 is not None and not hmac.compare_digest(
        document.sha256, pinned_sha256.strip().lower()
    ):
        raise _error(
            ConfigErrorCode.CK_CFG_053,
            path,
            f"organisation policy does not match {ORG_POLICY_SHA256_ENV}",
            "the file changed since the pin was set; check it with your security team",
        )
    secrets = find_plaintext_secrets(document.data, source=str(path), text=document.text)
    if secrets:
        raise _as_policy_error(ConfigError(secrets), path, ConfigErrorCode.CK_CFG_050)
    try:
        policy = OrgPolicy.model_validate(document.data)
    except ValidationError as error:
        raise OrgPolicyError(_validation_issues(error, path)) from None
    if policy.expires is not None and policy.expires < today:
        raise _error(
            ConfigErrorCode.CK_CFG_056,
            path,
            f"organisation policy expired on {policy.expires.isoformat()}",
            "ask the issuing security team for a current policy",
        )
    return LoadedOrgPolicy(policy=policy, path=path, sha256=document.sha256, origin=origin)


def discover_org_policies(
    env: Mapping[str, str],
    *,
    project_root: Path,
    system_paths: Sequence[Path] | None = None,
    today: date | None = None,
) -> tuple[LoadedOrgPolicy, ...]:
    """Every policy that applies to this run: existing system files, then the variable's file.

    ``system_paths`` defaults to ``paths.system_policy_paths()`` and is injected by tests only.

    Raises:
        OrgPolicyError: codes 050 to 053 and 056; nothing is returned partially.
    """
    candidates = paths.system_policy_paths() if system_paths is None else tuple(system_paths)
    today = today or date.today()  # noqa: DTZ011 - policy dates are calendar dates
    loaded = [
        _load_one(path, "system", project_root=project_root, today=today, pinned_sha256=None)
        for path in candidates
        if path.exists()
    ]
    named = env.get(ORG_POLICY_ENV, "").strip()
    if named:
        pin = env.get(ORG_POLICY_SHA256_ENV, "").strip() or None
        loaded.append(
            _load_one(
                Path(named).expanduser(),
                "env",
                project_root=project_root,
                today=today,
                pinned_sha256=pin,
            )
        )
    return tuple(loaded)
