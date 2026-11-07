"""Apply a validated rename plan to a source text.

Owning epic: E09. Issue E09-04. Normative layout: docs/ARCHITECTURE.md section 3.

The edits are applied from the last to the first so that every earlier offset stays valid. The
plan is validated against the source first; a plan that fails the check produces no text at all
(I4). The result is a plain ``str``: the caller decides what it is (a sanitised payload segment).
"""

from codekavach.core.models import RawCode
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.plan import RenamePlan


def apply_plan(source: RawCode, plan: RenamePlan) -> str:
    """The text of ``source`` with every edit of ``plan`` applied.

    Raises:
        PseudonymError: the plan is invalid for this source, or the source is not valid UTF-8.
    """
    data = source.expose().encode("utf-8", errors="surrogateescape")
    plan.validate(data)
    pieces = bytearray(data)
    for edit in reversed(plan.edits):
        pieces[edit.start_byte : edit.end_byte] = edit.replacement.encode("utf-8")
    try:
        return bytes(pieces).decode("utf-8")
    except UnicodeDecodeError as error:
        raise PseudonymError("applying the plan produced invalid text") from error
