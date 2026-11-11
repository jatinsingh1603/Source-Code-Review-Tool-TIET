"""Loading rule files, catalogues and packs safely (E16-01).

Owning epic: E16. A rule file can come from the repository being scanned, so it is untrusted:

* one bounded read through one descriptor, a regular file that is not a symlink (CWE-22, CWE-59),
  at most ``MAX_RULE_BYTES`` (CWE-400), strict UTF-8;
* ``yaml.safe_load`` semantics only (no Python objects are ever built), and anchors, aliases and
  explicit tags are refused before parsing so a file cannot become an expansion bomb (CWE-776);
* every regular expression is compiled once at load time;
* nothing in a file is executed, and no message contains file content.
"""

import os
import re
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import ValidationError

from codekavach.analysis.rules.dsl import RuleDef, _RuleModel
from codekavach.analysis.rules.errors import (
    RuleEncodingError,
    RuleFileTooLargeError,
    RuleLoadError,
    RulePackError,
    RulePathError,
    RuleShapeError,
    RuleYamlError,
)
from codekavach.analysis.rules.pack import (
    Catalogue,
    PackManifest,
    RulePack,
    catalogue_ids,
    pack_checksum,
)
from codekavach.analysis.rules.validate import RuleCode, RuleIssue, validate_rules
from codekavach.config import Settings
from codekavach.core.log import get_logger

MAX_RULE_BYTES: Final = 1024 * 1024
PACK_FILE: Final = "pack.yaml"
RULE_SUFFIXES: Final = (".yaml", ".yml")
BUNDLE_SUFFIX: Final = ".ckrules"
MAX_ERRORS_SHOWN: Final = 5
_SUSPECT: Final = re.compile(r"[&*!]")
_DEEP_INDENT: Final = re.compile(r"^ {65,}\S", re.MULTILINE)
SHALLOW_BRACKETS: Final = 50
SHALLOW_DASHES: Final = 100
MAX_DEPTH: Final = 32
_OPENERS: Final = (
    yaml.FlowSequenceStartToken,
    yaml.FlowMappingStartToken,
    yaml.BlockSequenceStartToken,
    yaml.BlockMappingStartToken,
)
_CLOSERS: Final = (yaml.FlowSequenceEndToken, yaml.FlowMappingEndToken, yaml.BlockEndToken)
_LOADER: Final = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_log = get_logger(__name__)


def read_text(path: Path, *, limit: int = MAX_RULE_BYTES) -> str:
    """The text of one regular, non-symlink file of at most ``limit`` bytes, as strict UTF-8."""
    try:
        info = os.lstat(path)
    except OSError:
        raise RulePathError(path, "cannot be read") from None
    if stat.S_ISLNK(info.st_mode):
        raise RulePathError(path, "is a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise RulePathError(path, "is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise RulePathError(path, "cannot be read") from None
    try:
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    except OSError:
        raise RulePathError(path, "cannot be read") from None
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise RuleFileTooLargeError(path, f"is larger than {limit} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleEncodingError(path, "is not valid UTF-8") from None


def _needs_token_scan(text: str) -> bool:
    """True when ``text`` could hold an anchor, alias, tag or deep nesting.

    The fast path keeps nesting provably small without parsing: at most ``SHALLOW_BRACKETS``
    flow brackets, no indentation beyond ``SHALLOW_INDENT`` and at most ``SHALLOW_DASHES`` list
    markers. Anything else is scanned token by token, with a depth limit.
    """
    return bool(
        _SUSPECT.search(text)
        or text.count("[") + text.count("{") > SHALLOW_BRACKETS
        or text.count("- ") > SHALLOW_DASHES
        or _DEEP_INDENT.search(text)
    )


def _scan_tokens(text: str, path: Path | str) -> None:
    depth = 0
    for token in yaml.scan(text, Loader=_LOADER):
        if isinstance(token, (yaml.AnchorToken, yaml.AliasToken, yaml.TagToken)):
            raise RuleYamlError(path, "anchors, aliases and tags are not allowed")
        if isinstance(token, _OPENERS):
            depth += 1
            if depth > MAX_DEPTH:
                raise RuleYamlError(path, f"is nested deeper than {MAX_DEPTH} levels")
        elif isinstance(token, _CLOSERS):
            depth -= 1


def parse_yaml(text: str, path: Path | str) -> Any:
    """Parse ``text`` with the safe loader, refusing anchors, aliases, tags and deep nesting."""
    try:
        if _needs_token_scan(text):
            _scan_tokens(text, path)
        return yaml.load(text, Loader=_LOADER)  # noqa: S506 - SafeLoader, no object construction
    except RuleYamlError:
        raise
    except (yaml.YAMLError, RecursionError, ValueError):
        raise RuleYamlError(path, "is not valid YAML") from None


def _shape[M: _RuleModel](path: Path | str, model: type[M], data: object) -> M:
    if not isinstance(data, dict):
        raise RuleShapeError(path, "must be a mapping of fields")
    try:
        return model.model_validate(data)
    except ValidationError as error:
        shown = [
            ".".join(str(part) for part in item["loc"]) + ": " + item["msg"]
            for item in error.errors(include_input=False, include_url=False)
        ]
        more = len(shown) - MAX_ERRORS_SHOWN
        text = "; ".join(shown[:MAX_ERRORS_SHOWN]) + (f"; and {more} more" if more > 0 else "")
        raise RuleShapeError(path, text) from None


def load_rule_file(path: Path) -> RuleDef:
    """Read, parse and shape-check one rule file; compiles its regular expressions."""
    rule = _shape(path, RuleDef, parse_yaml(read_text(path), path))
    try:
        _ = rule.compiled_regexes
    except re.error:
        raise RuleShapeError(path, "a regular expression does not compile") from None
    return rule


def load_catalogue(path: Path) -> Catalogue:
    """Read one catalogue file."""
    return _shape(path, Catalogue, parse_yaml(read_text(path), path))


def load_manifest(path: Path) -> PackManifest:
    """Read one ``pack.yaml``."""
    return _shape(path, PackManifest, parse_yaml(read_text(path), path))


def _yaml_files(directory: Path) -> Iterator[Path]:
    """Rule-like files below ``directory`` in a fixed order; symlinks are listed, not followed."""
    for current, names, files in os.walk(directory, followlinks=False):
        names.sort()
        for name in sorted(files):
            if name.endswith(RULE_SUFFIXES):
                yield Path(current) / name


@dataclass
class PackScan:
    """The result of reading one pack directory: the pack (when usable) and every problem."""

    directory: Path
    licence_dir: str
    pack: RulePack | None = None
    issues: list[RuleIssue] = field(default_factory=list)
    rule_paths: dict[str, Path] = field(default_factory=dict)


def _relative(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _unusable(scan: PackScan, error: RuleLoadError, base: Path) -> None:
    where = _relative(Path(error.path), base)
    scan.issues.append(RuleIssue(RuleCode.FILE_UNUSABLE, error.reason, path=where))


def _where(scan: PackScan, rule_id: str | None, base: Path) -> str | None:
    path = scan.rule_paths.get(rule_id or "")
    return _relative(path, base) if path is not None else None


def scan_pack(directory: Path) -> PackScan:
    """Read ``directory`` (``<licence>/packs/<id>``), collecting every problem."""
    directory = Path(directory)
    licence_root = directory.parent.parent
    scan = PackScan(directory, licence_root.name)
    base = licence_root.parent
    try:
        manifest = load_manifest(directory / PACK_FILE)
    except RuleLoadError as error:
        _unusable(scan, error, base)
        return scan
    rules: list[RuleDef] = []
    for path in _yaml_files(directory):
        if path.name == PACK_FILE and path.parent == directory:
            continue
        try:
            rule = load_rule_file(path)
        except RuleLoadError as error:
            _unusable(scan, error, base)
            continue
        rules.append(rule)
        scan.rule_paths.setdefault(rule.id, path)
    catalogues: list[Catalogue] = []
    catalogue_root = licence_root / "catalogues"
    if catalogue_root.is_dir():
        for path in _yaml_files(catalogue_root):
            try:
                catalogues.append(load_catalogue(path))
            except RuleLoadError as error:
                _unusable(scan, error, base)
    found = validate_rules(
        rules, catalogue_ids=catalogue_ids(catalogues), licence_dir=scan.licence_dir
    )
    scan.issues.extend(
        RuleIssue(item.code, item.message, item.rule_id, _where(scan, item.rule_id, base))
        for item in found
    )
    if manifest.licence.lower() != scan.licence_dir.lower():
        message = "pack.yaml licence differs from the licence directory"
        scan.issues.append(RuleIssue(RuleCode.LICENCE_MISMATCH, message, path=PACK_FILE))
    scan.pack = RulePack(
        id=manifest.id,
        version=manifest.version,
        licence=manifest.licence,
        description=manifest.description,
        languages=manifest.languages,
        rules=tuple(sorted(rules, key=lambda item: item.id)),
        catalogues=tuple(catalogues),
        checksum=pack_checksum(rules),
    )
    return scan


def load_pack(directory: Path) -> RulePack:
    """Load one pack; raises ``RulePackError`` with the issues when it is not valid."""
    scan = scan_pack(directory)
    if scan.issues or scan.pack is None:
        raise RulePackError(directory, tuple(scan.issues))
    return scan.pack


def default_rules_root() -> Path | None:
    """The ``rules/`` directory of a source checkout, or ``None`` when there is none."""
    candidate = Path(__file__).resolve().parents[4] / "rules"
    return candidate if candidate.is_dir() else None


def licence_directories(rules_root: Path) -> list[Path]:
    """The licence directories under ``rules_root`` (``mit`` first, the rest sorted)."""
    found = [item for item in sorted(rules_root.iterdir()) if (item / "packs").is_dir()]
    return sorted(found, key=lambda item: (item.name != "mit", item.name))


def _inside(path: Path, roots: Sequence[Path]) -> bool:
    resolved = Path(os.path.realpath(path))
    return any(resolved.is_relative_to(Path(os.path.realpath(root))) for root in roots)


def _packs_of(path: Path) -> list[Path]:
    if (path / PACK_FILE).is_file():
        return [path]
    packs = path / "packs"
    if packs.is_dir():
        return [item for item in sorted(packs.iterdir()) if (item / PACK_FILE).is_file()]
    raise RulePathError(path, "is neither a pack nor a licence directory of packs")


def load_packs(
    settings: Settings,
    *,
    rules_root: Path | None = None,
    allowed_roots: Sequence[Path] | None = None,
) -> list[RulePack]:
    """The packs named by ``engines.rule_packs`` and ``engines.rule_paths``.

    With ``engines.native.rules`` off, nothing is loaded. ``allowed_roots`` confines
    ``engines.rule_paths`` (an untrusted project passes its own root); a path that is a symlink
    or resolves elsewhere raises ``RulePathError``. Needs no network.
    """
    if not settings.engines.native.rules:
        return []
    from codekavach.analysis.rules.bundle import read_bundle  # noqa: PLC0415 - avoids a cycle

    loaded: dict[str, RulePack] = {}

    def add(pack: RulePack) -> None:
        if pack.id in loaded:
            raise RuleLoadError(pack.id, "a pack with this id is already loaded")
        loaded[pack.id] = pack

    root = rules_root if rules_root is not None else default_rules_root()
    for name in settings.engines.rule_packs:
        candidates = [d / "packs" / name for d in licence_directories(root)] if root else []
        found = [item for item in candidates if (item / PACK_FILE).is_file()]
        if not found:
            _log.warning("rule_pack_not_found", pack=name)
            continue
        add(load_pack(found[0]))
    for configured in settings.engines.rule_paths:
        path = Path(configured).expanduser().absolute()
        if path.is_symlink():
            raise RulePathError(path, "is a symbolic link")
        if allowed_roots is not None and not _inside(path, allowed_roots):
            raise RulePathError(path, "is outside the allowed roots")
        if path.is_file() and path.suffix == BUNDLE_SUFFIX:
            for pack in read_bundle(path):
                add(pack)
        else:
            for directory in _packs_of(path):
                add(load_pack(directory))
    return list(loaded.values())
