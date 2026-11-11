"""Performance budget of the SARIF reader (E14-02).

A log of 25,000 results (GitHub's per-run ceiling, about 20 MB here) must be converted in under
8 seconds. The 400 MB memory budget of the issue is not asserted: there is no portable resident
set measurement in the standard library, and this test reports the size of the log instead.
"""

import json
from pathlib import Path

import pytest

from codekavach.analysis.engines.sarif.ingest import ingest_sarif
from tests.support.perf import budget, measure
from tests.support.sarif import location, numbered_source, region, write_tree

pytestmark = pytest.mark.perf

RESULTS = 25_000


def big_log() -> bytes:
    rules = [
        {"id": f"rule-{n}", "properties": {"tags": ["security", f"external/cwe/cwe-{79 + n % 20}"]}}
        for n in range(200)
    ]
    results = [
        {
            "ruleId": f"rule-{n % 200}",
            "ruleIndex": n % 200,
            "level": ("error", "warning", "note")[n % 3],
            "message": {"text": f"finding number {n} " + "detail " * 20},
            "locations": [
                location(f"src/f{n % 40}.py", at=region(1 + n % 190, 3, 1 + n % 190, 30))
            ],
            "partialFingerprints": {"primaryLocationLineHash": f"{n:08x}:1"},
        }
        for n in range(RESULTS)
    ]
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "big", "version": "1.0", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(document).encode("utf-8")


def test_25000_results_in_under_eight_seconds(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path / "view", {f"src/f{n}.py": numbered_source(200, 60) for n in range(40)}
    )
    data = big_log()
    assert len(data) > 10 * 1024 * 1024

    def convert() -> None:
        found = ingest_sarif(data, engine_id="fake", root=root, engine_version="1.0")
        assert len(found) == RESULTS

    assert measure(convert, repeat=1) < budget(8.0)
