"""Deliberate privacy defects for the mutation harness (E28-03).

Each ``PrivacyDefect`` breaks one named control. ``apply_defect`` installs it with a
``pytest.MonkeyPatch``; the harness in ``tests/privacy/test_mutation_harness.py`` runs the tests
named in ``DEFECT_EXPECTATIONS`` in a subprocess with the defect active (through the pytest plugin
at the bottom of this module, selected by ``CODEKAVACH_PRIVACY_DEFECT``) and asserts that every
named test fails. A green suite is then evidence that the suite notices these breakages, not an
assumption.

``SCANNER_DEFECTS`` holds one "scanner removed" defect per leak scanner id, so registering a new
scanner without a covering defect fails ``test_every_leak_scanner_has_a_defect``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Final

import pytest

DEFECT_VARIABLE: Final = "CODEKAVACH_PRIVACY_DEFECT"


class PrivacyDefect(StrEnum):
    """The named defects. ``scanner_removed:<id>`` values are one per registered leak scanner."""

    GUARD_ALLOWS = "guard_allows"
    DETECTOR_NO_SPANS = "detector_no_spans"
    REDACTOR_IDENTITY = "redactor_identity"
    LEDGER_DROPS_PREV_HASH = "ledger_drops_prev_hash"
    POLICY_BASE_ONLY = "policy_base_only"
    EXPOSURE_NEVER_INCREMENTS = "exposure_never_increments"
    SCANNER_REMOVED_RESIDUAL_SECRET = "scanner_removed:residual_secret"
    SCANNER_REMOVED_VAULT_ORIGINAL = "scanner_removed:vault_original"
    SCANNER_REMOVED_DOMAIN_TERM = "scanner_removed:domain_term"
    SCANNER_REMOVED_RESIDUAL_PII = "scanner_removed:residual_pii"
    SCANNER_REMOVED_BUDGET = "scanner_removed:budget"
    SCANNER_REMOVED_AGGREGATION = "scanner_removed:aggregation"


SCANNER_DEFECTS: Final = frozenset(
    d for d in PrivacyDefect if d.value.startswith("scanner_removed:")
)

_I6 = "tests/privacy/test_i6_ledger.py"
_SCANNERS = "tests/unit/privacy/test_egress_scanners.py"
_GUARD = "tests/privacy/test_egress_guard.py"
_REDACTION = "tests/privacy/test_redaction_invariants.py"

# The tests each defect must make fail. Node ids are relative to the repository root.
DEFECT_EXPECTATIONS: Final[Mapping[PrivacyDefect, frozenset[str]]] = {
    PrivacyDefect.GUARD_ALLOWS: frozenset(
        {
            f"{_GUARD}::test_a_guard_with_no_scanners_lets_nothing_out",
            f"{_GUARD}::test_a_blocked_request_mints_nothing",
        }
    ),
    PrivacyDefect.DETECTOR_NO_SPANS: frozenset(
        {
            "tests/unit/privacy/detect/test_runner.py::test_detectors_run_and_their_spans_are_resolved",
            f"{_REDACTION}::test_i6_no_value_reaches_an_error_a_repr_or_a_report",
        }
    ),
    PrivacyDefect.REDACTOR_IDENTITY: frozenset(
        {
            "tests/unit/privacy/redact/test_redactor.py::test_a_span_is_replaced_by_its_typed_placeholder",
            f"{_REDACTION}::test_i6_no_value_reaches_an_error_a_repr_or_a_report",
        }
    ),
    PrivacyDefect.LEDGER_DROPS_PREV_HASH: frozenset(
        {"tests/privacy/test_ledger_tamper.py::test_intact_chain_verifies"}
    ),
    PrivacyDefect.POLICY_BASE_ONLY: frozenset(
        {"tests/unit/privacy/policy/test_engine.py::test_path_axis_tightens"}
    ),
    PrivacyDefect.EXPOSURE_NEVER_INCREMENTS: frozenset(
        {"tests/unit/privacy/test_aggregation.py::test_union_not_sum"}
    ),
    PrivacyDefect.SCANNER_REMOVED_RESIDUAL_SECRET: frozenset(
        {f"{_SCANNERS}::test_the_six_scanners_register_with_stable_ids"}
    ),
    PrivacyDefect.SCANNER_REMOVED_VAULT_ORIGINAL: frozenset(
        {f"{_I6}::test_a_body_with_an_original_is_blocked_with_vault_identifier"}
    ),
    PrivacyDefect.SCANNER_REMOVED_DOMAIN_TERM: frozenset(
        {f"{_I6}::test_a_domain_term_in_the_body_is_blocked_with_domain_term"}
    ),
    PrivacyDefect.SCANNER_REMOVED_RESIDUAL_PII: frozenset(
        {f"{_SCANNERS}::test_the_six_scanners_register_with_stable_ids"}
    ),
    PrivacyDefect.SCANNER_REMOVED_BUDGET: frozenset(
        {f"{_SCANNERS}::test_the_six_scanners_register_with_stable_ids"}
    ),
    PrivacyDefect.SCANNER_REMOVED_AGGREGATION: frozenset(
        {f"{_SCANNERS}::test_the_six_scanners_register_with_stable_ids"}
    ),
}

# Four defects for the pull-request job: redaction, the guard, the ledger and the policy.
SMOKE: Final = (
    PrivacyDefect.REDACTOR_IDENTITY,
    PrivacyDefect.GUARD_ALLOWS,
    PrivacyDefect.LEDGER_DROPS_PREV_HASH,
    PrivacyDefect.POLICY_BASE_ONLY,
)


def _without_scanner(scanner_id: str) -> Any:
    from codekavach.privacy.egress import scanners  # noqa: PLC0415

    real = scanners.default_scanners

    def default_scanners(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return tuple(s for s in real(*args, **kwargs) if s.id != scanner_id)

    return scanners, "default_scanners", default_scanners


def apply_defect(monkeypatch: pytest.MonkeyPatch, defect: PrivacyDefect) -> None:
    """Install ``defect``; ``monkeypatch.undo()`` removes it."""
    # Imports are local: the plugin loads before the code under test is imported.
    from codekavach.core.models.egress import EgressRecord  # noqa: PLC0415
    from codekavach.privacy.detect import runner  # noqa: PLC0415
    from codekavach.privacy.egress import guard  # noqa: PLC0415
    from codekavach.privacy.egress.aggregation import ExposureAccount  # noqa: PLC0415
    from codekavach.privacy.policy.engine import PolicyEngine  # noqa: PLC0415
    from codekavach.privacy.redact.redactor import Redactor  # noqa: PLC0415

    if defect is PrivacyDefect.GUARD_ALLOWS:
        monkeypatch.setattr(guard.EgressGuard, "_block_code", staticmethod(lambda hits, err: None))
    elif defect is PrivacyDefect.DETECTOR_NO_SPANS:
        monkeypatch.setattr(runner, "_run_one", lambda *a, **k: ())
    elif defect is PrivacyDefect.REDACTOR_IDENTITY:
        real = Redactor.redact

        def identity(self: Any, text: Any, spans: Any, **kwargs: Any) -> Any:
            return real(self, text, (), **kwargs)

        monkeypatch.setattr(Redactor, "redact", identity)
    elif defect is PrivacyDefect.LEDGER_DROPS_PREV_HASH:
        real_seal = EgressRecord.seal.__func__  # type: ignore[attr-defined]

        def seal(cls: Any, **kwargs: Any) -> Any:
            kwargs["prev"] = (
                None
                if kwargs.get("prev") is None
                else kwargs["prev"].model_copy(update={"entry_hash": "0" * 64})
            )
            return real_seal(cls, **kwargs)

        monkeypatch.setattr(EgressRecord, "seal", classmethod(seal))  # type: ignore[arg-type]
    elif defect is PrivacyDefect.POLICY_BASE_ONLY:
        real_resolve = PolicyEngine._resolve

        def base_only(self: Any, path: str, tier: Any, *args: Any) -> Any:
            decision = real_resolve(self, path, tier, *args)
            base = decision.contributions[0]
            return type(decision)(
                level=base.level or decision.level,
                never_send=False,
                classifications=(),
                contributions=(base,),
                policy_hash=decision.policy_hash,
            )

        monkeypatch.setattr(PolicyEngine, "_resolve", base_only)
    elif defect is PrivacyDefect.EXPOSURE_NEVER_INCREMENTS:
        monkeypatch.setattr(ExposureAccount, "record", lambda *a, **k: None)
    elif defect in SCANNER_DEFECTS:
        target, name, value = _without_scanner(defect.value.split(":", 1)[1])
        monkeypatch.setattr(target, name, value)
    else:  # pragma: no cover - the enumeration and this function change together
        raise ValueError(f"no implementation for {defect}")


# --- the pytest plugin the harness selects with -p tests.support.mutate --------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Install the defect named by ``CODEKAVACH_PRIVACY_DEFECT`` for the whole session."""
    name = os.environ.get(DEFECT_VARIABLE)
    if not name:
        return
    patch = pytest.MonkeyPatch()
    apply_defect(patch, PrivacyDefect(name))
    config.add_cleanup(patch.undo)
