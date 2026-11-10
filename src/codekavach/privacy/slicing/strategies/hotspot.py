"""Hotspots and the discovery slice built around them (E11-03).

Owning epic: E11.

The deterministic stage is silent about code it has no rule for. The discovery task asks the model
to look there too, on regions marked security-relevant (docs/research/INSIGHTS.md section 2.2 item
2), and to be budgeted and reported apart from triage because its precision is lower.

``HotspotSource.hotspots(parsed, symbols)`` is the input protocol: any rule engine can implement it.
``SyntacticHotspots`` is the minimal implementation of this issue, so the strategy is testable
before the rule engine exists. It marks calls by the names of *published* interfaces (the standard
library and the well-known packages, never a client name), in seven families: authorisation check,
cryptographic operation, deserialisation, filesystem access, database query, process execution and
template rendering. A name table is a starting point, not a rule set; the rule engine (E16)
replaces it.

``HotspotStrategy`` cuts the enclosing function of a hotspot candidate with its callees' stubs, as
the enclosing-function strategy does, and tags the slice ``purpose = "discover"`` and
``strategy = "hotspot"``, so the llm-review stage can apply a separate budget and the report can
list discovery results apart from triage. A discovery slice never consumes the triage budget.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from tree_sitter import Node

from codekavach.core.models import (
    Candidate,
    CodeSlice,
    Language,
    Location,
    SlicePurpose,
    SliceStrategy,
)
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import first, last
from codekavach.privacy.slicing.strategies.enclosing import (
    EnclosingFunctionStrategy,
    slice_id_for,
)
from codekavach.privacy.slicing.stubs import StubStats


class HotspotFamily(StrEnum):
    """The kind of security-relevant region."""

    AUTHORISATION = "authorisation"
    CRYPTOGRAPHY = "cryptography"
    DESERIALISATION = "deserialisation"
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    PROCESS = "process"
    TEMPLATE = "template"


@dataclass(frozen=True, slots=True)
class Hotspot:
    """A marked region: the lines of the call, and the family it belongs to."""

    location: Location
    family: HotspotFamily


class HotspotSource(Protocol):
    """Where hotspots come from: the rule engine, or the syntactic starter below."""

    def hotspots(self, parsed: ParsedFile, symbols: SymbolTable) -> Sequence[Hotspot]:
        """Every hotspot of one parsed file, in source order."""
        ...


_CALLS: Final = frozenset({"call", "call_expression", "new_expression"})
_F: Final = HotspotFamily
# Full dotted names of published interfaces, checked first.
_EXACT: Final[dict[str, HotspotFamily]] = {
    "os.system": _F.PROCESS,
    "os.popen": _F.PROCESS,
    "os.execv": _F.PROCESS,
    "subprocess.run": _F.PROCESS,
    "subprocess.call": _F.PROCESS,
    "subprocess.check_call": _F.PROCESS,
    "subprocess.check_output": _F.PROCESS,
    "subprocess.Popen": _F.PROCESS,
    "child_process.exec": _F.PROCESS,
    "child_process.execSync": _F.PROCESS,
    "child_process.spawn": _F.PROCESS,
    "child_process.spawnSync": _F.PROCESS,
    "child_process.execFile": _F.PROCESS,
    "pickle.load": _F.DESERIALISATION,
    "pickle.loads": _F.DESERIALISATION,
    "marshal.loads": _F.DESERIALISATION,
    "yaml.load": _F.DESERIALISATION,
    "eval": _F.DESERIALISATION,
    "open": _F.FILESYSTEM,
    "os.remove": _F.FILESYSTEM,
    "os.unlink": _F.FILESYSTEM,
    "shutil.rmtree": _F.FILESYSTEM,
    "shutil.copy": _F.FILESYSTEM,
    "fs.readFile": _F.FILESYSTEM,
    "fs.readFileSync": _F.FILESYSTEM,
    "fs.writeFile": _F.FILESYSTEM,
    "fs.writeFileSync": _F.FILESYSTEM,
    "fs.unlink": _F.FILESYSTEM,
    "hashlib.md5": _F.CRYPTOGRAPHY,
    "hashlib.sha1": _F.CRYPTOGRAPHY,
    "hashlib.new": _F.CRYPTOGRAPHY,
    "hmac.new": _F.CRYPTOGRAPHY,
    "crypto.createHash": _F.CRYPTOGRAPHY,
    "crypto.createCipheriv": _F.CRYPTOGRAPHY,
    "crypto.createDecipheriv": _F.CRYPTOGRAPHY,
    "crypto.randomBytes": _F.CRYPTOGRAPHY,
    "jwt.decode": _F.CRYPTOGRAPHY,
    "render_template_string": _F.TEMPLATE,
    "jinja2.Template": _F.TEMPLATE,
    "Markup": _F.TEMPLATE,
    "ejs.render": _F.TEMPLATE,
    "handlebars.compile": _F.TEMPLATE,
}
# The last segment of a method call, whatever its receiver.
_METHODS: Final[dict[str, HotspotFamily]] = {
    "execute": _F.DATABASE,
    "executemany": _F.DATABASE,
    "executescript": _F.DATABASE,
    "raw": _F.DATABASE,
    "query": _F.DATABASE,
    "render_template": _F.TEMPLATE,
    "render_to_string": _F.TEMPLATE,
}
# Words in the name of a called function that mark an authorisation check.
_AUTHORISATION_WORDS: Final = (
    "authoriz",
    "authoris",
    "permission",
    "is_admin",
    "isadmin",
    "has_role",
)


def _callee(call: Node) -> str:
    target = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    return "" if target is None or target.text is None else target.text.decode("utf-8", "replace")


_ALIASES: Final = {"cp": "child_process", "childProcess": "child_process", "proc": "child_process"}


def _family(callee: str) -> HotspotFamily | None:
    head, dot, rest = callee.partition(".")
    if dot and head in _ALIASES:
        callee = f"{_ALIASES[head]}.{rest}"
    if callee in _EXACT:
        return _EXACT[callee]
    name = callee.rsplit(".", 1)[-1]
    if "." in callee and name in _METHODS:
        return _METHODS[name]
    lowered = name.lower()
    if any(word in lowered for word in _AUTHORISATION_WORDS):
        return HotspotFamily.AUTHORISATION
    return None


class SyntacticHotspots:
    """Marks calls to published interfaces by name; the starter before the rule engine."""

    def hotspots(self, parsed: ParsedFile, symbols: SymbolTable) -> Sequence[Hotspot]:
        """Every call of ``parsed`` that belongs to a family, in source order."""
        del symbols  # the names of published interfaces are read from the call itself
        if parsed.tree is None or parsed.language not in {
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
        }:
            return ()
        found: list[tuple[int, Hotspot]] = []
        stack = [parsed.tree.root_node]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type not in _CALLS:
                continue
            family = _family(_callee(node))
            if family is not None:
                where = Location(path=parsed.path, start_line=first(node), end_line=last(node))
                found.append((node.start_byte, Hotspot(where, family)))
        return tuple(h for _, h in sorted(found, key=lambda item: item[0]))


class HotspotStrategy:
    """Cuts the function around a hotspot for the discovery task."""

    name = SliceStrategy.HOTSPOT

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The discovery slice for ``candidate``."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        base, stats = EnclosingFunctionStrategy().build_with_stats(candidate, parsed, budget=budget)
        tagged = base.model_copy(
            update={
                "id": slice_id_for(candidate, list(base.segments), self.name),
                "strategy": self.name,
                "purpose": SlicePurpose.DISCOVER,
            }
        )
        return tagged, stats
