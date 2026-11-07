"""Weak cryptography: a broken password hash (CWE-327) and a fixed initialisation vector (CWE-329).

Owning epic: E13. MVP; extended by E16.

Two rules share one module because they read the same crypto call sites.

``weak-password-hash`` fires on MD5 or SHA-1 (``hashlib.md5``, ``hashlib.new("sha1")``,
``crypto.createHash("md5")``) when the enclosing function or the statement is about a password. A
modern password hash (scrypt, bcrypt, argon2, PBKDF2) is not on the list.

``static-iv`` fires on a block-cipher call (``AES.new``, ``modes.CBC``, ``createCipheriv``) whose IV
or nonce is a literal, ``bytes(16)`` or a name assigned one. A value from ``os.urandom``,
``secrets`` or ``crypto.randomBytes`` is the safe form.
"""

import re
from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    function_name,
    identifiers_in,
    is_literal,
    last_segment,
    resolve_string,
    static_text,
)
from codekavach.core.models import Severity

WEAK_HASH: Final = Rule(
    slug="weak-password-hash",
    cwe=327,
    severity=Severity.HIGH,
    message="A password is hashed with an algorithm that is broken or far too fast.",
)
STATIC_IV: Final = Rule(
    slug="static-iv",
    cwe=329,
    severity=Severity.MEDIUM,
    message="A block cipher is given a fixed initialisation vector instead of a random one.",
)
BROKEN_ALGORITHMS: Final = frozenset({"md5", "md4", "sha1", "sha-1"})
HASH_CALLS: Final = frozenset({"hashlib.md5", "hashlib.sha1", "md5", "sha1", "md5.new", "sha1.new"})
NAMED_HASH_CALLS: Final = frozenset({"hashlib.new", "crypto.createhash", "createhash"})
CIPHER_CLASSES: Final = frozenset({"aes", "des", "des3", "blowfish", "cast", "arc2", "arc4"})
IV_MODES: Final = frozenset({"cbc", "cfb", "ofb", "ctr", "gcm"})
PASSWORD_WORD: Final = re.compile(r"pass(word|wd|phrase)|pwd|credential", re.IGNORECASE)
CONSTRUCTORS: Final = frozenset(
    {"bytes", "bytearray", "buffer.from", "buffer.alloc", "bytes.fromhex", "uint8array"}
)
STATEMENT_PARENTS: Final = frozenset({"block", "module", "program", "statement_block"})


def _statement_of(node: Node) -> Node:
    current = node
    while current.parent is not None and current.parent.type not in STATEMENT_PARENTS:
        current = current.parent
    return current


def _about_password(node: Node) -> bool:
    function = enclosing_function(node)
    name = function_name(function) if function is not None else None
    if name and PASSWORD_WORD.search(name):
        return True
    return any(PASSWORD_WORD.search(word) for word in identifiers_in(_statement_of(node)))


def _is_constant(node: Node) -> bool:
    if is_literal(node):
        return True
    if node.type in CALL_TYPES:
        arguments, _ = call_arguments(node)
        name = (callee_name(node) or "").lower()
        return name in CONSTRUCTORS and all(_is_constant(item) for item in arguments)
    if node.type in {"binary_operator", "binary_expression"}:
        children = node.named_children
        return len(children) >= 2 and all(_is_constant(child) for child in children)
    return False


class WeakCryptoMatcher(NodeMatcher):
    """Finds broken password hashes and fixed initialisation vectors."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for a weak password hash or a static IV at this call."""
        name = (callee_name(node) or "").lower()
        if not name:
            return
        if self._broken_hash(node, name) and _about_password(node):
            yield Hit(WEAK_HASH, node)
        iv = self._iv_argument(node, name)
        if iv is not None and _is_constant(resolve_string(iv, enclosing_function(node), ctx.root)):
            yield Hit(STATIC_IV, node)

    @staticmethod
    def _broken_hash(node: Node, name: str) -> bool:
        if name in HASH_CALLS:
            return True
        if name not in NAMED_HASH_CALLS:
            return False
        arguments, _ = call_arguments(node)
        return bool(arguments) and static_text(arguments[0]).lower() in BROKEN_ALGORITHMS

    @staticmethod
    def _iv_argument(node: Node, name: str) -> Node | None:
        arguments, keywords = call_arguments(node)
        prefix, _, member = name.rpartition(".")
        if member == "new" and last_segment(prefix) in CIPHER_CLASSES:
            return keywords.get("iv") or keywords.get("nonce") or _at(arguments, 2)
        if prefix.endswith("modes") and member in IV_MODES:
            return _at(arguments, 0)
        if member == "createcipheriv":
            return _at(arguments, 2)
        return None


def _at(items: list[Node], index: int) -> Node | None:
    return items[index] if len(items) > index else None
