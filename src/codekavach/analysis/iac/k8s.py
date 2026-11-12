# ruff: noqa: PERF401
"""Kubernetes manifest checks."""

import re
from typing import Any, Final

from codekavach.analysis.iac.common import Issue, YMap, falsy, load_yaml, truthy, walk
from codekavach.core.models import Confidence, Severity

WORKLOADS: Final = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
)
_SECRET_NAME: Final = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)", re.I)


def is_manifest(text: str) -> bool:
    """True when some document has ``apiVersion`` and ``kind``."""
    return any(isinstance(d, YMap) and "apiVersion" in d and "kind" in d for d in load_yaml(text))


def check_k8s(text: str) -> list[Issue]:
    """Privileged containers, root users, hostPath, host namespaces, no limits, floating tags."""
    issues: list[Issue] = []
    for doc in load_yaml(text):
        if not (isinstance(doc, YMap) and doc.get("kind") in WORKLOADS):
            continue
        for node in walk(doc):
            if isinstance(node, YMap):
                _pod_level(node, issues)
                containers = node.get("containers")
                if isinstance(containers, list):
                    for c in containers:
                        if isinstance(c, YMap):
                            _container(c, node, issues)
    return issues


def _pod_level(spec: YMap, issues: list[Issue]) -> None:
    for flag, rule, what in (
        ("hostNetwork", "iac.k8s.host-network", "the host network namespace"),
        ("hostPID", "iac.k8s.host-pid", "the host PID namespace"),
        ("hostIPC", "iac.k8s.host-ipc", "the host IPC namespace"),
    ):
        if truthy(spec.get(flag)):
            issues.append(
                Issue(rule, spec.line_of(flag), Severity.HIGH, 250, f"Pod shares {what}.")
            )
    volumes = spec.get("volumes")
    if isinstance(volumes, list):
        for vol in volumes:
            if isinstance(vol, YMap) and "hostPath" in vol:
                issues.append(
                    Issue(
                        "iac.k8s.host-path",
                        vol.line_of("hostPath"),
                        Severity.HIGH,
                        250,
                        "Pod mounts a hostPath volume, exposing the node filesystem.",
                    )
                )
    sc = spec.get("securityContext")
    if isinstance(sc, YMap) and sc.get("runAsUser") == 0:
        issues.append(
            Issue(
                "iac.k8s.run-as-root",
                sc.line_of("runAsUser"),
                Severity.MEDIUM,
                250,
                "Pod security context runs as UID 0.",
            )
        )


def _container(c: YMap, pod: YMap, issues: list[Issue]) -> None:
    name = str(c.get("name", "container"))
    sc: Any = c.get("securityContext")
    psc: Any = pod.get("securityContext")
    if isinstance(sc, YMap):
        if truthy(sc.get("privileged")):
            issues.append(
                Issue(
                    "iac.k8s.privileged",
                    sc.line_of("privileged"),
                    Severity.CRITICAL,
                    250,
                    f"Container '{name}' is privileged.",
                )
            )
        if sc.get("runAsUser") == 0 or falsy(sc.get("runAsNonRoot")):
            issues.append(
                Issue(
                    "iac.k8s.run-as-root",
                    sc.line_of("runAsUser") if "runAsUser" in sc else sc.line_of("runAsNonRoot"),
                    Severity.MEDIUM,
                    250,
                    f"Container '{name}' may run as root.",
                )
            )
        if truthy(sc.get("allowPrivilegeEscalation")):
            issues.append(
                Issue(
                    "iac.k8s.privilege-escalation",
                    sc.line_of("allowPrivilegeEscalation"),
                    Severity.MEDIUM,
                    269,
                    f"Container '{name}' allows privilege escalation.",
                )
            )
    elif not (isinstance(psc, YMap) and truthy(psc.get("runAsNonRoot"))):
        issues.append(
            Issue(
                "iac.k8s.no-security-context",
                c.line,
                Severity.LOW,
                250,
                f"Container '{name}' sets no securityContext (runAsNonRoot is not enforced).",
                Confidence.MEDIUM,
            )
        )
    resources = c.get("resources")
    limits = resources.get("limits") if isinstance(resources, YMap) else None
    if not limits:
        issues.append(
            Issue(
                "iac.k8s.no-limits",
                c.line_of("resources") if "resources" in c else c.line,
                Severity.LOW,
                770,
                f"Container '{name}' has no resource limits.",
            )
        )
    image = str(c.get("image", ""))
    if image and "@sha256:" not in image:
        tail = image.rsplit("/", 1)[-1]
        if ":" not in tail or tail.endswith(":latest"):
            issues.append(
                Issue(
                    "iac.k8s.latest-image",
                    c.line_of("image"),
                    Severity.LOW,
                    1104,
                    f"Container '{name}' uses a floating image tag.",
                )
            )
    env = c.get("env")
    if isinstance(env, list):
        for item in env:
            if (
                isinstance(item, YMap)
                and _SECRET_NAME.search(str(item.get("name", "")))
                and item.get("value")
            ):
                issues.append(
                    Issue(
                        "iac.k8s.secret-in-env",
                        item.line,
                        Severity.HIGH,
                        798,
                        f"Container '{name}' sets {item.get('name')} as a literal; use a "
                        "Secret reference.",
                    )
                )
