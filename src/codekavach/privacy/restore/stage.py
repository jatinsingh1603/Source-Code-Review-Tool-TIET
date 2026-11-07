"""``RestoreStage``: from ``verdicts.raw`` to ``verdicts.restored`` (E10-02).

Owning epic: E10 (issue E10-02). Category ``RESTORE``, so the failure policy is fail closed
(invariant I4): a stage-level exception aborts the scan's egress path, while one malformed verdict
is reported with ``RunContext.fail_item`` through ``guard_item`` and the others are still restored
and published. The vault is opened once for the stage and closed when the block exits, even on an
exception; it is opened without creating a file (``create=False``), because a scan that restores
without a vault has nothing to restore against.

The slice key is ``keys.SLICES`` (E13-02); privacy-prepare writes the original slice per candidate.
The stage reads ``candidates`` only as a declared dependency; it does not use its content.
"""

from pydantic import BaseModel

from codekavach.core.log import get_logger
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.verdict import CandidateVerdict
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.items import RESTORE_FAILED, guard_item
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactTypeError
from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.restore.errors import RestoreError
from codekavach.privacy.restore.models import RestoredVerdict
from codekavach.privacy.vault.keys import KeySource
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import Vault

_log = get_logger("codekavach.privacy.restore")


def _read[Model: BaseModel](ctx: RunContext, key: str, model: type[Model]) -> list[Model]:
    """The models under ``key``, whether the store persisted them or holds them transiently.

    Payloads hold ``SanitisedText`` and slices hold ``RawCode``, which a persisted artefact does
    not reload, so the store may keep them as transient objects; both forms are read here.
    """
    try:
        return ctx.artefacts.get_list(key, model)
    except ArtefactTypeError:
        value = ctx.artefacts.get_object(key)
        if isinstance(value, (list, tuple)) and all(isinstance(item, model) for item in value):
            return list(value)
        raise RestoreError(f"artefact {key!r} does not hold the expected records") from None


class RestoreStage:
    """Restores every raw verdict of the scan against its payload and slice."""

    name = "restore"
    requires = frozenset({keys.VERDICTS_RAW, keys.PAYLOADS_SANITISED, keys.SLICES, keys.CANDIDATES})
    provides = frozenset({keys.VERDICTS_RESTORED})
    category = StageCategory.RESTORE
    version = "1"

    def run(self, ctx: RunContext) -> None:
        """Restore each verdict, isolate failures per candidate and publish the restored list."""
        verdicts = _read(ctx, keys.VERDICTS_RAW, CandidateVerdict)
        if not verdicts:
            ctx.artefacts.put(keys.VERDICTS_RESTORED, [])
            return
        payloads = {
            payload.candidate_id: payload
            for payload in _read(ctx, keys.PAYLOADS_SANITISED, SanitisedPayload)
        }
        slices = {slice_.candidate_id: slice_ for slice_ in _read(ctx, keys.SLICES, CodeSlice)}
        if ctx.state_dir is None:
            raise RestoreError("restoration needs the state directory of the vault")
        restored: list[RestoredVerdict] = []
        with Vault(
            vault_path(ctx.state_dir),
            KeySource(ctx.config.privacy.vault.key_source),
            settings=ctx.config,
            create=False,
        ) as vault:
            engine = RestoreEngine(vault, scan_id=ctx.scan_id)
            for item in verdicts:
                with guard_item(ctx, str(item.candidate_id), RESTORE_FAILED):
                    payload = payloads.get(item.candidate_id)
                    slice_ = slices.get(item.candidate_id)
                    if payload is None or slice_ is None:
                        raise RestoreError("a verdict has no payload or no slice")
                    restored.append(engine.restore(item.verdict, payload, slice_))
        _log.info("verdicts_restored", count=len(restored), requested=len(verdicts))
        ctx.artefacts.put(keys.VERDICTS_RESTORED, restored)
