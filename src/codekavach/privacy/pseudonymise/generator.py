"""Salted, kind-preserving pseudonyms: the ``fn_1`` and ``var_3`` that replace internal names.

Owning epic: E09 (issue E09-01). Normative layout: docs/ARCHITECTURE.md section 3.

Invariant I5: the same scan salt and the same input give the same pseudonyms.

**Why a keyed hash, and not a counter or format-preserving encryption.** A counter assigned in
traversal order would make a token depend on the slice it was first seen in, so one function
renamed in two slices would get two tokens, which breaks the verdict cache, multi-slice reasoning
and reproducible experiments. A keyed hash depends only on the salt, the kind and the name.
Format-preserving encryption would give a cryptographic argument, but docs/research/INSIGHTS.md
section 4.3 records that the published guidance restricts the usable algorithm and that short
identifiers fall below its safe domain size. An HMAC-derived token plus the encrypted local vault
is therefore the default.

**How a number is chosen.** A payload should read ``fn_1``, ``fn_2``, not ``fn_1837462``, so the
HMAC decides the *order* of a kind's names and the number is the position in that order. A
position only exists relative to a set, so the numbering is a function of the salt and the set of
names of the scan. ``prepare`` takes that set; the symbol table holds it before the first payload
is built. Once a kind is prepared, a token does not depend on how many names were asked for
before it, or in which order: the slice being rewritten plays no part, which is what makes
cross-slice consistency and cache hits possible. Scanning a subset of the files is a different
set and gives a different numbering; that is what ``per_scan`` means.

A name that ``prepare`` did not see is numbered after the prepared ones when it is first asked
for. It stays unique and the numbering stays dense, and the token holds for the life of the
generator, but its number then depends on arrival order, so a caller that wants I5 for a name
must prepare it.

**Linkability is a setting, not a verdict.** ``privacy.pseudonym.link_mode = "per_scan"`` keeps
one generator for the scan: data flow stays intact across payloads and the verdict cache works, at
the cost of cross-request linkability at the provider (metric M8 in docs/research/INSIGHTS.md
section 4.3). ``per_request`` builds a fresh generator per payload with ``for_request``, which
reduces that linkability and has two costs: the verdict cache is defeated, because the same code
no longer produces the same payload, and reasoning about one function across two slices is no
longer possible, because it has a different name in each. Neither mode is claimed to be better;
both are measurable.

**Role hints are off by default.** A hint such as ``var_3_authz`` comes from the local analysis
result and is accepted only as a member of ``SecurityRole``, so a label taken from the original
name cannot be expressed. Do not enable ``privacy.pseudonym.role_hints`` in a client engagement
until the leakage arm has measured it: the ablation is required and has not been run, so no effect
is claimed here in either direction.

This module claims no resistance level against identifier recovery; the leakage harness measures
that.
"""

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Self

from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.errors import PseudonymError

if TYPE_CHECKING:
    from codekavach.parsing.symbols import Symbol


class PseudonymKind(StrEnum):
    """The syntactic role a token keeps; the value is the token prefix."""

    FN = "fn"
    CLS = "cls"
    VAR = "var"
    PARAM = "param"
    FIELD = "field"
    MOD = "mod"
    CONST = "const"
    FILE = "file"


class SecurityRole(StrEnum):
    """Analysis-derived role labels; the closed set is what keeps a name out of a hint."""

    CRED = "cred"
    AUTHZ = "authz"
    SANITISED = "sanitised"
    TAINTED = "tainted"
    SINK_ARG = "sink_arg"


# The ``Symbol.kind`` vocabulary of E07-03. A test keeps this complete.
SYMBOL_KINDS: Final[Mapping[str, PseudonymKind]] = {
    "function": PseudonymKind.FN,
    "method": PseudonymKind.FN,
    "class": PseudonymKind.CLS,
    "variable": PseudonymKind.VAR,
    "parameter": PseudonymKind.PARAM,
    "field": PseudonymKind.FIELD,
    "module": PseudonymKind.MOD,
    "import": PseudonymKind.MOD,
    "constant": PseudonymKind.CONST,
}
PSEUDONYM_SHAPE: Final = (
    r"^(fn|cls|var|param|field|mod|const|file)_[1-9][0-9]*"
    r"(_(cred|authz|sanitised|tainted|sink_arg))?$"
)
_TOKEN = re.compile(PSEUDONYM_SHAPE)
# ``prefix_digits`` can match none of these; they guard against a future change of format, because
# a meaningful token misleads a model more than a meaningless one (INSIGHTS section 3.3 item 4).
_MEANINGFUL: Final = frozenset(
    {
        "account",
        "admin",
        "auth",
        "balance",
        "customer",
        "login",
        "password",
        "payment",
        "secret",
        "token",
        "user",
    }
)


class PseudonymGenerator:
    """Turns names into tokens for one scan, or for one request in ``per_request`` mode.

    The salt is read once, into a keyed HMAC object that is copied for each name: its bytes are
    not kept in an attribute, and no ``repr``, log line or message here shows them.
    """

    __slots__ = ("_mac", "_numbers", "_role_hints")

    def __init__(self, salt: ScanSalt, *, role_hints: bool = False) -> None:
        self._mac = hmac.new(salt.reveal(), digestmod=hashlib.sha256)
        self._numbers: dict[PseudonymKind, dict[str, int]] = {kind: {} for kind in PseudonymKind}
        self._role_hints = role_hints

    def __repr__(self) -> str:
        return f"PseudonymGenerator({sum(map(len, self._numbers.values()))} names)"

    def for_request(self, nonce: bytes) -> Self:
        """A fresh generator under ``HMAC-SHA256(salt, nonce)``, unlinkable from this one."""
        mac = self._mac.copy()
        mac.update(nonce)
        return type(self)(ScanSalt(mac.digest()), role_hints=self._role_hints)

    def prepare(self, kind: PseudonymKind | str, originals: Iterable[str]) -> None:
        """Number ``originals`` of ``kind`` in HMAC order, after any name already numbered.

        Call this with every name of the kind before the first token, so that the numbering is a
        function of the salt and the set alone. Names already numbered keep their tokens: a token
        does not change within a generator's life.
        """
        pseudonym_kind = PseudonymKind(kind)
        numbers = self._numbers[pseudonym_kind]
        unseen = {original for original in originals if original not in numbers}
        for original in sorted(unseen, key=lambda name: self._digest(pseudonym_kind, name)):
            numbers[original] = self._next_number(pseudonym_kind, numbers)

    def token(
        self, kind: PseudonymKind | str, original: str, role: SecurityRole | None = None
    ) -> str:
        """The token of ``original``; ``role`` is appended when role hints are on."""
        if role is not None and not isinstance(role, SecurityRole):
            raise TypeError("a role hint is a SecurityRole, never text from the code")
        pseudonym_kind = PseudonymKind(kind)
        numbers = self._numbers[pseudonym_kind]
        number = numbers.get(original)
        if number is None:
            number = numbers[original] = self._next_number(pseudonym_kind, numbers)
        base = f"{pseudonym_kind.value}_{number}"
        return f"{base}_{role.value}" if role is not None and self._role_hints else base

    def assignments(self) -> tuple[tuple[PseudonymKind, str, str], ...]:
        """Every ``(kind, original, token)`` numbered so far, by kind and then by number.

        The originals are raw client data: this is for building the mapping batch (E09-05) and
        nothing else. Role hints are not part of the token here.
        """
        return tuple(
            (kind, original, f"{kind.value}_{number}")
            for kind, numbers in self._numbers.items()
            for original, number in sorted(numbers.items(), key=lambda item: item[1])
        )

    def token_for_symbol(self, symbol: "Symbol", role: SecurityRole | None = None) -> str:
        """The token of a symbol, through the ``Symbol.kind`` vocabulary of E07-03."""
        return self.token(SYMBOL_KINDS[symbol.kind], symbol.name, role)

    def _digest(self, kind: PseudonymKind, original: str) -> bytes:
        mac = self._mac.copy()
        mac.update(f"{kind.value}:{original}".encode("utf-8", "surrogatepass"))
        return mac.digest()

    @staticmethod
    def _next_number(kind: PseudonymKind, numbers: dict[str, int]) -> int:
        """The next free number; each new token is checked here, once."""
        number = len(numbers) + 1
        token = f"{kind.value}_{number}"
        if not _TOKEN.match(token) or token in _MEANINGFUL:
            raise PseudonymError("a generated token does not have the meaning-free shape")
        return number
