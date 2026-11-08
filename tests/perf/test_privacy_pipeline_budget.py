"""Performance budgets of privacy-prepare and llm-review (E13-02).

The issue sets 60 s for 200 candidates in privacy-prepare and 10 s for llm-review on the mock
provider. The KavachBank fixture has about ten candidates, so:

* privacy-prepare is projected: the stage time of the fixture run, fixed costs included, is scaled
  to 200 candidates. The fixed costs (key derivation, detector set-up) make the projection
  pessimistic, which is the safe direction for a budget;
* llm-review is measured: 200 requests go through the real guard, ledger and mock provider of the
  fixture's vault, cycling over its payloads.

Budgets are scaled by the performance factor.
"""

import time
from functools import partial
from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.llm.providers.mock import MockProvider
from codekavach.llm.tasks.triage import TriageTask
from codekavach.privacy.stages import open_egress_session
from tests.integration.test_privacy_pipeline import (
    ENV,
    PASSPHRASE_VARIABLE,
    copy_fixture,
    run_and_capture,
)
from tests.support.perf import assert_within_budget

pytestmark = pytest.mark.perf
CANDIDATES = 200
PREPARE_BUDGET_SECONDS = 60.0
REVIEW_BUDGET_SECONDS = 10.0


def test_the_two_stages_stay_within_their_budgets_at_200_candidates(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PASSPHRASE_VARIABLE, "synthetic passphrase for tests only")
    root: Path = copy_fixture(tmp_path_factory.mktemp("perf"))
    run = run_and_capture(root)
    count = len(run.payloads)
    assert count > 0
    prepare = next(s for s in run.outcome.result.stage_runs if s.stage == "privacy-prepare")
    assert_within_budget(
        prepare.duration_ms / 1000 / count * CANDIDATES,
        PREPARE_BUDGET_SECONDS,
        label="privacy-prepare projected to 200 candidates",
    )

    loaded = load_settings(
        target=root,
        env={
            "CODEKAVACH_HOME": str(root.parent / "home"),
            **ENV,
            "CODEKAVACH_PRIVACY__EGRESS__RATE_PER_MINUTE": "100000",
        },
    )
    provider, task = MockProvider(), TriageTask()
    started = time.perf_counter()
    with open_egress_session(
        settings=loaded.settings,
        state_dir=Path(run.outcome.state_dir),
        scan_id=run.outcome.scan.id,
        consent=None,
    ) as session:
        for index in range(CANDIDATES):
            payload = run.payloads[index % count]
            request = provider.prepare(task, payload)
            result = session.dispatch(
                request,
                provider=provider.id,
                model=request.model,
                task=task.name,
                payload=payload,
                respond=partial(provider.respond, request),
                static_text=task.static_text(payload),
            )
            assert result.kind == "answered"
    assert_within_budget(
        time.perf_counter() - started, REVIEW_BUDGET_SECONDS, label="200 mock requests"
    )
