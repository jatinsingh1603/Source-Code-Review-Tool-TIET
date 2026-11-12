"""The structured privacy attestation of one stored scan (E25-03, E28-03).

``build_attestation(state_dir, scan_id, settings)`` is the single function that the report, the
server (``GET /scans/{id}/privacy``) and ``codekavach privacy score`` call. It reads only
metadata: the policy rows, the disclosure figures and the ledger; the payload texts are read from
the ledger solely to count placeholders and to run the verbatim residual-term search. The result
holds no path, pattern, identifier or code. ``Attestation.to_api()`` is the REST shape;
``Attestation.digest()`` and ``sign()`` make it tamper-evident.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.disclosure import DisclosureRows
from codekavach.core.models.enums import PrivacyLevel, TrustTier
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.attest import PrivacyScore, ScoreInputs, compute_privacy_score
from codekavach.privacy.egress.ledger import open_reader
from codekavach.privacy.policy.records import PolicyDecisionRow

_log = get_logger(__name__)


class ZeroLeakResult(BaseModel):
    """Verbatim residual-term search over the ledger payloads."""

    model_config = ConfigDict(frozen=True)

    checked: bool = False
    terms_checked: int = 0
    occurrences: int = 0

    @property
    def passed(self) -> bool:
        """True when a check ran and found nothing."""
        return self.checked and self.occurrences == 0


class Attestation(BaseModel):
    """What was prepared, under which policy, what left, and how private it was."""

    model_config = ConfigDict(frozen=True)

    scan_id: str
    level: str
    provider: str | None = None
    model: str | None = None
    provider_tier: str = "local"
    payloads: int = 0
    blocked: int = 0
    withheld: int = 0
    placeholders_by_type: dict[str, int] = Field(default_factory=dict)
    pseudonyms: int = 0
    tokens_sent: int = 0
    chain_ok: bool = True
    ledger_entries: int = 0
    ledger_head_hash: str | None = None
    zero_leak: ZeroLeakResult = ZeroLeakResult()
    levels_by_candidate: dict[str, int] = Field(default_factory=dict)
    policy_hash: str | None = None
    policy_rules: dict[str, int] = Field(default_factory=dict)
    disclosure: dict[str, str] = Field(default_factory=dict)
    score: PrivacyScore
    attestation_text: str

    @property
    def privacy_score(self) -> int:
        """The summary score (0..100); the components are in ``score``."""
        return self.score.score

    def to_api(self) -> dict[str, Any]:
        """The ``GET /scans/{id}/privacy`` body (a superset of the documented contract)."""
        return {
            "level": self.level,
            "payloads": self.payloads,
            "blocked": self.blocked,
            "placeholders_by_type": self.placeholders_by_type,
            "pseudonyms": self.pseudonyms,
            "tokens_sent": self.tokens_sent,
            "chain_ok": self.chain_ok,
            "zero_leak": {
                "checked": self.zero_leak.terms_checked,
                "occurrences": self.zero_leak.occurrences,
                "passed": self.zero_leak.passed,
            },
            "privacy_score": self.privacy_score,
            "score_components": [c.model_dump() for c in self.score.components],
            "score_formula": self.score.formula,
            "score_caps": list(self.score.caps),
            "provider": self.provider,
            "model": self.model,
            "provider_tier": self.provider_tier,
            "withheld": self.withheld,
            "levels_by_candidate": self.levels_by_candidate,
            "policy_hash": self.policy_hash,
            "policy_rules": self.policy_rules,
            "disclosure": self.disclosure,
            "ledger_head_hash": self.ledger_head_hash,
            "ledger_entries": self.ledger_entries,
            "attestation_text": self.attestation_text,
        }

    def digest(self) -> str:
        """SHA-256 of the canonical JSON of the attestation."""
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def sign(self, key: bytes) -> str:
        """HMAC-SHA256 over ``digest()``; a verifier with the same key recomputes it."""
        return hmac.new(key, self.digest().encode(), hashlib.sha256).hexdigest()


def _terms(settings: Settings) -> tuple[str, ...]:
    terms = [t for t in settings.privacy.domain_terms if t.strip()]
    file = settings.privacy.domain_terms_file
    if file is not None:
        try:
            lines = Path(file).read_text(encoding="utf-8").splitlines()
            terms.extend(x.strip() for x in lines if x.strip() and not x.startswith("#"))
        except OSError:
            _log.info("attestation_terms_file_unreadable")
    return tuple(dict.fromkeys(terms))


def _text(att: dict[str, Any]) -> str:
    lines = [
        f"Scan {att['scan_id']} was prepared at privacy level {att['level']} "
        f"for provider {att['provider'] or 'none'} ({att['tier']} trust tier).",
        f"{att['payloads']} sanitised payload(s) were recorded, {att['blocked']} blocked by the "
        f"egress guard and {att['withheld']} withheld by policy.",
        f"Disclosed {att['pct']}% of repository lines; residual-term check: {att['leak']}.",
        f"Ledger chain: {'verified' if att['chain_ok'] else 'NOT verified'}"
        f" ({att['entries']} entries). Policy hash: {att['policy_hash'] or 'none'}.",
        f"Privacy score {att['score']}/100 (summary of named components; see score_components).",
    ]
    if att["local"]:
        lines.append(
            "The provider answered inside the trust boundary: the ledger shows what would have "
            "left the environment, not what did."
        )
    return " ".join(lines)


def _gather(
    store: OnDiskArtefactStore | None, settings: Settings
) -> tuple[list[PolicyDecisionRow], dict[str, str]]:
    rows: list[PolicyDecisionRow] = []
    disclosure: dict[str, str] = {}
    if store is not None:
        if store.has(keys.POLICY_DECISIONS):
            rows = store.get_list(keys.POLICY_DECISIONS, PolicyDecisionRow)
        if store.has(keys.DISCLOSURE):
            disclosure = dict(store.get(keys.DISCLOSURE, DisclosureRows).rows)
    return rows, disclosure


def build_attestation(  # noqa: PLR0915 - one linear gather-and-summarise
    state_dir: Path | StateLayout,
    scan_id: str,
    settings: Settings,
    *,
    level: PrivacyLevel | None = None,
) -> Attestation:
    """The attestation of ``scan_id`` stored below ``state_dir``.

    ``level`` is the scan's recorded privacy level; it defaults to ``settings.privacy.level``.
    """
    scan_level = str(level or settings.privacy.level)
    layout = state_dir if isinstance(state_dir, StateLayout) else StateLayout(state_dir)
    try:
        store: OnDiskArtefactStore | None = OnDiskArtefactStore.open_existing(layout, scan_id)
    except Exception:  # noqa: BLE001 - a scan with no records still has an attestation
        store = None
    rows, disclosure = _gather(store, settings)

    provider = model = None
    tier = TrustTier.LOCAL
    try:
        provider, config = settings.llm.selected_provider()
        tier = config.effective_trust_tier
    except Exception:  # noqa: BLE001 - llm disabled
        _log.info("attestation_no_provider")

    chain_ok, entries, head, blocked, tokens = True, 0, None, 0, 0
    reader = None
    try:
        reader = open_reader(layout, settings=settings)
        chain_ok = reader.verify_chain().ok
        for record in reader.records(scan_id):
            entries += 1
            head = record.entry_hash
            provider, model = record.provider, record.model
            tokens += record.token_counts.prompt
            blocked += record.outcome.value == "blocked"
    except Exception:  # noqa: BLE001 - nothing sent means no ledger to read
        _log.info("attestation_ledger_unreadable")
        reader = None

    payload_levels: list[PrivacyLevel] = []
    placeholders: Counter[str] = Counter()
    pseudonyms = 0
    token_owners: Counter[str] = Counter()
    terms = _terms(settings)
    occurrences = 0
    checked = False
    count = 0
    if store is not None and reader is not None:
        try:
            from codekavach.privacy.inspect_source import open_payload_source  # noqa: PLC0415

            for payload in open_payload_source(layout, scan_id, settings).payloads(scan_id):
                count += 1
                payload_levels.append(payload.level)
                pseudonyms += payload.pseudonym_count
                for ref in payload.placeholders:
                    placeholders[ref.subtype] += ref.occurrences
                    token_owners[ref.token] += 1
                if terms:
                    checked = True
                    text = payload.text.expose().lower()
                    occurrences += sum(text.count(t.lower()) for t in terms)
        except Exception:  # noqa: BLE001 - attest what can be read
            _log.info("attestation_payloads_unreadable")
    if not terms and count:
        checked = False
    if store is not None and not count and store.has(keys.PAYLOAD_INDEX):
        from codekavach.core.models.disclosure import PayloadStub  # noqa: PLC0415

        stubs = store.get_list(keys.PAYLOAD_INDEX, PayloadStub)
        count = len(stubs)
        payload_levels = [s.level for s in stubs]
        pseudonyms = sum(s.pseudonym_count for s in stubs)

    by_level = Counter(row.level.value for row in rows if not row.withheld)
    withheld = sum(1 for row in rows if row.withheld)
    rules = Counter(row.rule_key for row in rows)
    hashes = {row.policy_hash for row in rows}
    pct = float(disclosure.get("repository_fraction_pct", "0") or 0)
    shared = sum(1 for n in token_owners.values() if n > 1)
    score = compute_privacy_score(
        ScoreInputs(
            payload_levels=tuple(payload_levels),
            repo_pct=pct,
            budget_ceiling_pct=settings.privacy.egress.aggregation_budget_pct,
            residual_checked=checked,
            residual_occurrences=occurrences,
            tokens_total=len(token_owners),
            tokens_shared=shared,
            chain_ok=chain_ok,
        )
    )
    leak = (
        "not checked (no terms configured)"
        if not checked
        else f"{len(terms)} term(s), {occurrences} occurrence(s)"
    )
    local = tier is TrustTier.LOCAL
    text = _text(
        {
            "scan_id": scan_id,
            "level": scan_level,
            "provider": provider,
            "tier": tier.value,
            "payloads": count,
            "blocked": blocked,
            "withheld": withheld,
            "pct": f"{pct:.2f}",
            "leak": leak,
            "chain_ok": chain_ok,
            "entries": entries,
            "policy_hash": next(iter(hashes))[:16] if len(hashes) == 1 else None,
            "score": score.score,
            "local": local,
        }
    )
    return Attestation(
        scan_id=scan_id,
        level=scan_level,
        provider=provider,
        model=model,
        provider_tier=tier.value,
        payloads=count,
        blocked=blocked,
        withheld=withheld,
        placeholders_by_type=dict(sorted(placeholders.items())),
        pseudonyms=pseudonyms,
        tokens_sent=tokens,
        chain_ok=chain_ok,
        ledger_entries=entries,
        ledger_head_hash=head,
        zero_leak=ZeroLeakResult(
            checked=checked, terms_checked=len(terms), occurrences=occurrences
        ),
        levels_by_candidate=dict(sorted(by_level.items())),
        policy_hash=next(iter(hashes)) if len(hashes) == 1 else None,
        policy_rules=dict(sorted(rules.items())),
        disclosure=disclosure,
        score=score,
        attestation_text=text,
    )
