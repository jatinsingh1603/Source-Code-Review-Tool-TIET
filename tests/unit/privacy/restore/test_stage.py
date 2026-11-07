"""``RestoreStage`` (E10-02): declarations, per-item failure isolation and the published list.

The stage is not registered under the ``codekavach.stages`` entry points yet: its inputs come from
stages that arrive with E13-02, and a registered stage whose input nothing provides makes every
default scan fail to plan. E13-02 registers it with the stages that feed it.
"""

from pathlib import Path

import pytest

from codekavach.core.models.ids import CandidateId
from codekavach.core.models.verdict import CandidateVerdict
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.items import RESTORE_FAILED
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore import stage as stage_module
from codekavach.privacy.restore.errors import RestoreError
from codekavach.privacy.restore.models import RestoredVerdict
from codekavach.privacy.restore.stage import RestoreStage
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import Vault
from tests.support.factories import CANDIDATE_ID, make_payload, make_slice, make_verdict
from tests.support.pipeline import make_run_context

pytestmark = pytest.mark.privacy

KEY = SecretBytes(b"\x2e" * 32)
OTHER = CandidateId("cand_01ARYZ6S410000000000000007")
UNPAIRED = CandidateId("cand_01ARYZ6S410000000000000008")


@pytest.fixture
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A state directory whose vault opens with a test key, since the keyring is not available."""
    monkeypatch.setattr(
        stage_module,
        "Vault",
        lambda path, source, settings=None, create=False: Vault(
            path, KeySource.EPHEMERAL, KEY, create=create
        ),
    )
    return tmp_path / "state"


def write_mapping(state: Path, scan_id: str) -> None:
    """Store the pseudonyms of one scan in the vault the stage will open."""
    with Vault(vault_path(state), KeySource.EPHEMERAL, KEY) as vault:
        vault.put(
            MappingBatch(
                scan_id,
                (
                    MappingEntry("param_1", "account_id", PseudonymKind.PARAM, "accounts"),
                    MappingEntry("fn_1", "accrue_premium_interest", PseudonymKind.FN, "accounts"),
                ),
            )
        )


def test_the_declarations_match_the_pipeline_table() -> None:
    info = describe_stage(RestoreStage())
    assert info.name == "restore"
    assert info.requires == frozenset(
        {keys.VERDICTS_RAW, keys.PAYLOADS_SANITISED, keys.SLICES, keys.CANDIDATES}
    )
    assert info.provides == frozenset({keys.VERDICTS_RESTORED})
    assert info.category is StageCategory.RESTORE
    assert info.failure_policy is FailurePolicy.FAIL_CLOSED


def test_a_failing_candidate_is_reported_and_the_rest_are_published(state_dir: Path) -> None:
    store = InMemoryArtefactStore()
    ctx = make_run_context(store=store, state_dir=state_dir).for_stage("restore")
    write_mapping(state_dir, ctx.scan_id)
    taints = make_verdict(reasoning="Taints param_1.", cited_lines=(3,), impact="", remediation="")
    unknown = make_verdict(reasoning="Calls fn_77 now.", impact="", remediation="")
    store.put(
        keys.VERDICTS_RAW,
        [
            CandidateVerdict(candidate_id=CANDIDATE_ID, verdict=taints),
            CandidateVerdict(candidate_id=UNPAIRED, verdict=taints),
            CandidateVerdict(candidate_id=OTHER, verdict=unknown),
        ],
    )
    store.put(
        keys.PAYLOADS_SANITISED,
        [make_payload(), make_payload(candidate_id=OTHER)],
        persist=False,
    )
    store.put(keys.SLICES, [make_slice(), make_slice(candidate_id=OTHER)], persist=False)

    RestoreStage().run(ctx)

    restored = store.get_list(keys.VERDICTS_RESTORED, RestoredVerdict)
    assert [item.candidate_id for item in restored] == [CANDIDATE_ID, OTHER]
    assert restored[0].reasoning == "Taints account_id."
    assert restored[1].verdict_dropped is True
    failures = [
        (failure.stage, failure.item_id, failure.error_code)
        for failure in ctx.item_failures.snapshot()
    ]
    assert failures == [("restore", str(UNPAIRED), RESTORE_FAILED)]


def test_a_missing_state_directory_fails_the_stage() -> None:
    store = InMemoryArtefactStore()
    verdict = make_verdict(impact="", remediation="")
    store.put(keys.VERDICTS_RAW, [CandidateVerdict(candidate_id=CANDIDATE_ID, verdict=verdict)])
    store.put(keys.PAYLOADS_SANITISED, [], persist=False)
    store.put(keys.SLICES, [], persist=False)
    ctx = make_run_context(store=store, state_dir=None).for_stage("restore")
    with pytest.raises(RestoreError):
        RestoreStage().run(ctx)


def test_no_verdicts_publishes_an_empty_list(state_dir: Path) -> None:
    store = InMemoryArtefactStore()
    store.put(keys.VERDICTS_RAW, [])
    ctx = make_run_context(store=store, state_dir=state_dir).for_stage("restore")
    RestoreStage().run(ctx)
    assert store.get_list(keys.VERDICTS_RESTORED, RestoredVerdict) == []
