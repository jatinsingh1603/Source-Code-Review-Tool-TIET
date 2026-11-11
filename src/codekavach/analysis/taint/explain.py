"""The explain dump: why did, or did not, a path appear (E17-02).

Owning epic: E17. When ``taint.explain`` is true the stage writes, per function, a JSON file and a
Graphviz file with the blocks, the statements, the places and lattice values after each block and
the witnesses found. A rule author uses it when a path does not appear and they cannot see why.

**This is raw client data.** The dump holds places, callee names and locations in the clear. It is
written only under ``<state_dir>/taint/``, only when explicitly enabled, never into a report and
never into an artefact an LLM-category stage may require (invariant I2). The file names are hashes,
not paths.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Call,
    Goto,
    IRFunction,
    Loop,
    Stmt,
    Unknown,
)
from codekavach.analysis.taint.propagate import FlowWitness
from codekavach.analysis.taint.state import TaintState

DIRECTORY = "taint"


@dataclass(slots=True)
class Trace:
    """What the solver saw at the end of each block: place to labels and uncertainty."""

    blocks: dict[int, dict[str, list[str]]] = field(default_factory=dict)

    def record(self, states: dict[int, TaintState]) -> None:
        """Keep the settled out-state of every block."""
        for block, state in states.items():
            self.blocks[block] = {
                name: sorted(
                    f"{'unknown' if fact.uncertain else 'tainted'}:{','.join(sorted(fact.labels))}"
                    for fact in facts.values()
                )
                for name, (_, facts) in sorted(state.entries.items())
            }


def _line(stmt: Stmt) -> str:
    """One statement as a short label: operation, place names and line, no values."""
    if isinstance(stmt, Assign):
        return f"{stmt.target.text} = ... @{stmt.location.start_line}"
    if isinstance(stmt, Call):
        result = stmt.result.text if stmt.result is not None else "_"
        return f"{result} = {stmt.callee.text}(...) @{stmt.location.start_line}"
    if isinstance(stmt, Goto):
        return f"goto {stmt.target}"
    if isinstance(stmt, Unknown):
        return f"unknown {stmt.reason}"
    return stmt.op


def _targets(stmt: Stmt | None) -> tuple[int, ...]:
    if isinstance(stmt, Branch):
        return (stmt.then_block, stmt.else_block)
    if isinstance(stmt, Loop):
        return (stmt.body_block, stmt.exit_block)
    if isinstance(stmt, Goto):
        return (stmt.target,)
    return ()


def dump(function: IRFunction, flows: list[FlowWitness], trace: Trace) -> tuple[str, str]:
    """The JSON and Graphviz texts for one function."""
    blocks = [
        {
            "id": block.id,
            "statements": [_line(stmt) for stmt in block.stmts],
            "state": trace.blocks.get(block.id, {}),
        }
        for block in function.blocks
    ]
    witnesses = [
        {
            "source": flow.source_id,
            "label": flow.label,
            "sink": flow.sink.entry.id,
            "sink_line": flow.sink_location.start_line,
            "uncertain": flow.uncertain,
            "steps": [
                f"{step.role.value}@{step.location.start_line}: {step.note or ''}"
                for step in flow.steps
            ],
        }
        for flow in flows
    ]
    document = {"function": function.qualname, "blocks": blocks, "witnesses": witnesses}
    lines = ["digraph taint {", "  node [shape=box fontname=monospace];"]
    for block in function.blocks:
        text = "\\l".join(_line(stmt).replace('"', "'") for stmt in block.stmts)
        lines.append(f'  b{block.id} [label="b{block.id}\\l{text}\\l"];')
        last = block.stmts[-1] if block.stmts else None
        lines.extend(f"  b{block.id} -> b{target};" for target in _targets(last))
    lines.append("}")
    return json.dumps(document, indent=2, sort_keys=True) + "\n", "\n".join(lines) + "\n"


def write_dump(
    state_dir: Path, file_hash: str, function: IRFunction, flows: list[FlowWitness], trace: Trace
) -> Path:
    """Write the dump of one function under ``<state_dir>/taint/`` and return the JSON path."""
    directory = state_dir / DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    stem = hashlib.sha256(f"{file_hash}:{function.qualname}".encode()).hexdigest()[:24]
    text, graph = dump(function, flows, trace)
    json_path = directory / f"{stem}.json"
    json_path.write_text(text, encoding="utf-8")
    (directory / f"{stem}.dot").write_text(graph, encoding="utf-8")
    return json_path
