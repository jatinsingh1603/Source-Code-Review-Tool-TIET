"""CycloneDX 1.5 (primary) and SPDX 2.3 (export) bills of materials (E19-01).

Both are generated from a ``DependencyGraph`` with no network access. Component ``bom-ref`` is
the package URL, so the dependency graph survives the conversion.
"""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from codekavach import __version__
from codekavach.analysis.sca.model import DependencyGraph


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_of(integrity: str | None) -> list[dict[str, str]]:
    if not integrity:
        return []
    algo, _, value = integrity.partition("-") if "-" in integrity else integrity.partition(":")
    names = {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1"}
    if algo in names and value and all(c in "0123456789abcdefABCDEF" for c in value):
        return [{"alg": names[algo], "content": value}]
    return []


def to_cyclonedx(graph: DependencyGraph, name: str = "application") -> dict[str, Any]:
    """A CycloneDX 1.5 JSON document."""
    seen: dict[str, dict[str, Any]] = {}
    for dep in graph.dependencies:
        if dep.purl in seen:
            continue
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": dep.purl,
            "name": dep.name,
            "version": dep.version or "unspecified",
            "purl": dep.purl,
            "scope": "excluded" if dep.scope.startswith(("dev", "test")) else "required",
            "properties": [
                {"name": "codekavach:direct", "value": str(dep.direct).lower()},
                {"name": "codekavach:internal", "value": str(dep.is_internal).lower()},
                {"name": "codekavach:resolved_from", "value": dep.resolved_from},
            ],
        }
        hashes = _hash_of(dep.integrity)
        if hashes:
            component["hashes"] = hashes
        if dep.licence_ids:
            component["licenses"] = [{"license": {"id": lic}} for lic in dep.licence_ids]
        seen[dep.purl] = component
    depends: dict[str, set[str]] = {purl: set() for purl in seen}
    for src, dst in graph.edges:
        if src in depends and dst in seen:
            depends[src].add(dst)
    digest = hashlib.sha256("".join(sorted(seen)).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.UUID(digest[:32])}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {
                "components": [
                    {"type": "application", "name": "codekavach", "version": __version__}
                ]
            },
            "component": {"type": "application", "name": name, "bom-ref": "root"},
        },
        "components": list(seen.values()),
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(depends.items())
        ],
    }


def to_spdx(graph: DependencyGraph, name: str = "application") -> dict[str, Any]:
    """An SPDX 2.3 JSON document derived from the same inventory."""
    packages: list[dict[str, Any]] = []
    ids: dict[str, str] = {}
    for dep in graph.dependencies:
        if dep.purl in ids:
            continue
        spdx_id = f"SPDXRef-Package-{len(ids) + 1}"
        ids[dep.purl] = spdx_id
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": dep.name,
                "versionInfo": dep.version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": " AND ".join(dep.licence_ids) or "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep.purl,
                    }
                ],
            }
        )
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": i,
        }
        for i in ids.values()
    ]
    relationships += [
        {"spdxElementId": ids[a], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ids[b]}
        for a, b in graph.edges
        if a in ids and b in ids
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://codekavach.invalid/spdx/{uuid.uuid4()}",
        "creationInfo": {"created": _now(), "creators": [f"Tool: codekavach-{__version__}"]},
        "packages": packages,
        "relationships": relationships,
    }
