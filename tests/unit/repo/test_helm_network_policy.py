"""The Helm NetworkPolicy admits in-cluster callers only.

A NetworkPolicy ingress rule without ``from`` admits every source, including NodePort and
LoadBalancer traffic from outside the cluster. These tests render the chart with ``helm``.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parents[3] / "deploy" / "helm" / "codekavach"

pytestmark = pytest.mark.unit


def _ingress(*overrides: str) -> list[dict[str, Any]]:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")
    args = [helm, "template", "t", str(CHART)]
    for override in overrides:
        args += ["--set", override]
    rendered = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    for doc in yaml.safe_load_all(rendered):
        if isinstance(doc, dict) and doc.get("kind") == "NetworkPolicy":
            rules: list[dict[str, Any]] = doc["spec"]["ingress"]
            return rules
    pytest.fail("the chart renders no NetworkPolicy")


def test_default_ingress_admits_any_in_cluster_pod_only() -> None:
    assert _ingress() == [
        {"ports": [{"port": 8080, "protocol": "TCP"}], "from": [{"namespaceSelector": {}}]}
    ]


def test_configured_namespaces_are_the_only_sources() -> None:
    rules = _ingress("networkPolicy.ingressFromNamespaces={ingress-nginx}")
    assert [rule["from"] for rule in rules] == [
        [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}]
    ]
