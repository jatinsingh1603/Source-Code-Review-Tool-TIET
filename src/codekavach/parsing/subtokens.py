"""Splitting an identifier into its sub-words (E07-03).

Owning epic: E07.

``split_subtokens`` cuts a name at case and character-class transitions only: no dictionary, no
word list, no locale. The domain-term miner (E08-04) and the optional role-hint policy (E09-01)
both reason about the parts of a name and are leakage-relevant, so the split must be deterministic
and must not depend on anything that can drift between releases.

The rules, applied left to right:

* any character that is not a letter or a digit (``_``, ``-``, ``$``, ``.``) separates and is
  dropped, so leading, trailing and doubled separators produce no empty piece;
* a lower-case letter followed by an upper-case one starts a new piece (``accountID`` gives
  ``account``, ``ID``);
* in a run of capitals followed by a lower-case letter, the last capital starts the new piece
  (``HTTPServer`` gives ``HTTP``, ``Server``);
* a letter next to a digit starts a new piece (``utf8Decode`` gives ``utf``, ``8``, ``Decode``);
* a character with no case (for example a CJK ideograph) counts as lower case.
"""

from enum import Enum, auto


class _Class(Enum):
    UPPER = auto()
    LOWER = auto()
    DIGIT = auto()
    OTHER = auto()


def _classify(char: str) -> _Class:
    if char.isdigit():
        return _Class.DIGIT
    if char.isalpha():
        return _Class.UPPER if char.isupper() else _Class.LOWER
    return _Class.OTHER


def split_subtokens(name: str) -> tuple[str, ...]:
    """The sub-words of ``name`` in order, with their original case.

    ``accountIDForKYC_2`` gives ``("account", "ID", "For", "KYC", "2")`` and ``__init__`` gives
    ``("init",)``.
    """
    classes = [_classify(char) for char in name]
    pieces: list[str] = []
    start: int | None = None
    for index, kind in enumerate(classes):
        if kind is _Class.OTHER:
            if start is not None:
                pieces.append(name[start:index])
                start = None
            continue
        if start is None:
            start = index
            continue
        previous = classes[index - 1]
        following = classes[index + 1] if index + 1 < len(classes) else _Class.OTHER
        boundary = (
            (kind is _Class.UPPER and previous is _Class.LOWER)
            or (kind is _Class.UPPER and previous is _Class.UPPER and following is _Class.LOWER)
            or ((kind is _Class.DIGIT) != (previous is _Class.DIGIT))
        )
        if boundary:
            pieces.append(name[start:index])
            start = index
    if start is not None:
        pieces.append(name[start:])
    return tuple(pieces)


def normalise_subtoken(subtoken: str) -> str:
    """The case-folded form of a sub-word, for comparing sub-words regardless of case."""
    return subtoken.casefold()
