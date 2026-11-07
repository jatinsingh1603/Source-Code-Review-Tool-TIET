"""OS command injection (CWE-78): a shell command built from variable parts.

Owning epic: E13. MVP; extended by E16.

Sinks: ``os.system`` and ``os.popen``, the ``subprocess`` functions with ``shell=True``, and in
JavaScript ``exec`` and ``execSync`` (always a shell) plus ``spawn``, ``spawnSync`` and ``execFile``
with ``shell: true``. The matcher fires when the command is built at run time (or is a name taken
from the caller) and some variable part is not passed through a quoting function. A list of
arguments with no shell, and a command whose every variable part is quoted, are the safe forms.
"""

from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    is_escaped,
    is_literal,
    is_request_derived,
    resolve_string,
    string_parts,
    text_of,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="command-injection",
    cwe=78,
    severity=Severity.CRITICAL,
    message="A shell command is built from variable parts that are not quoted.",
)
ALWAYS_SHELL: Final = {
    "py": frozenset({"os.system", "os.popen", "commands.getoutput"}),
    "js": frozenset(
        {"exec", "execsync", "child_process.exec", "child_process.execsync", "cp.exec",
         "cp.execsync", "shelljs.exec", "execa.command"}
    ),
}  # fmt: skip
SHELL_WITH_FLAG: Final = {
    "py": frozenset(
        {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
         "subprocess.popen"}
    ),
    "js": frozenset(
        {"child_process.spawn", "child_process.spawnsync", "child_process.execfile", "spawn",
         "spawnsync", "execfile", "cp.spawn", "cp.spawnsync"}
    ),
}  # fmt: skip

NAME_TYPES: Final = frozenset({"identifier", "attribute", "member_expression", "subscript"})


def _shell_enabled(keywords: dict[str, Node]) -> bool:
    flag = keywords.get("shell")
    return flag is not None and text_of(flag).lower() == "true"


class CommandInjectionMatcher(NodeMatcher):
    """Finds shell commands assembled from unquoted variable parts."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for a shell call whose command is not safely quoted."""
        name = (callee_name(node) or "").lower()
        family = "py" if node.type == "call" else "js"
        arguments, keywords = call_arguments(node)
        if not arguments:
            return
        if name in SHELL_WITH_FLAG[family]:
            if not _shell_enabled(keywords):
                return
        elif name not in ALWAYS_SHELL[family]:
            return
        function = enclosing_function(node)
        command = resolve_string(arguments[0], function, ctx.root)
        parts = string_parts(command)
        if parts is None:
            if command.type in NAME_TYPES and is_request_derived(command, function, ctx.root):
                yield Hit(RULE, node)
            return
        if any(not is_literal(part) and not is_escaped(part) for part in parts):
            yield Hit(RULE, node)
