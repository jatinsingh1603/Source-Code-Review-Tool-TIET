"""Manifest and lock file parsers (E19-01).

``parse_manifest(path, text, read=...)`` returns the components one file declares. ``build_graph``
walks a set of files, prefers a lock file over the manifest next to it (the manifest then only
marks components ``direct`` and supplies the declared range), and records the file each version
came from in ``resolved_from``.

Supported: ``requirements*.txt`` (``-r``/``-c`` includes, ``--hash``, markers, editable, VCS and
path requirements), ``pyproject.toml`` (PEP 621, dependency groups, Poetry), ``poetry.lock``,
``uv.lock``, ``package.json``, ``package-lock.json`` (v1 to v3, without double counting),
``yarn.lock`` (classic and Berry), ``pnpm-lock.yaml``, ``pom.xml`` (properties), Gradle build
files, ``go.mod`` / ``go.sum``, ``Gemfile.lock``, ``composer.lock`` and ``Cargo.lock``.
Unparseable files are skipped and reported by name, never fatal.
"""

import json
import posixpath
import re
import tomllib
from collections.abc import Callable, Iterable
from typing import Any, Final

import yaml

from codekavach.analysis.sca.model import Dependency, DependencyGraph, make_purl

Reader = Callable[[str], str | None]

_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_PIN = re.compile(r"^(?:==|===)\s*([^\s,;]+)")
_PRIVATE_HINT = re.compile(
    r"(^|[-_/@])(internal|private|corp)([-_/]|$)|^@[a-z0-9-]*(internal|corp)"
)

REQUIREMENT_FILE = re.compile(r"^requirements([-_.][\w.-]*)?\.(txt|in)$|^constraints\.txt$")
LOCK_NAMES: Final = frozenset(
    {
        "poetry.lock",
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.sum",
        "Gemfile.lock",
        "composer.lock",
        "Cargo.lock",
    }
)
MANIFEST_NAMES: Final = frozenset(
    {"pyproject.toml", "package.json", "pom.xml", "go.mod", "composer.json", "Cargo.toml"}
    | {"build.gradle", "build.gradle.kts"}
)


def is_manifest_path(path: str) -> bool:
    """True when ``path`` names a file this module can parse."""
    name = posixpath.basename(path)
    if "node_modules/" in path or "/vendor/" in path or "/.venv/" in path:
        return False
    return bool(name in LOCK_NAMES or name in MANIFEST_NAMES or REQUIREMENT_FILE.match(name))


def _dep(
    eco: str,
    name: str,
    version: str,
    src: str,
    *,
    direct: bool = False,
    scope: str = "runtime",
    declared: str | None = None,
    line: int = 1,
    integrity: str | None = None,
    internal: bool = False,
    requires: Iterable[str] = (),
) -> Dependency:
    return Dependency(
        purl=make_purl(eco, name, version),
        name=name,
        version=version,
        ecosystem=eco,
        direct=direct,
        scope=scope,
        declared_range=declared,
        resolved_from=src,
        line=line,
        locations=(src,),
        is_internal=internal or bool(_PRIVATE_HINT.search(name)),
        integrity=integrity,
        requires=tuple(requires),
    )


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


# --------------------------------------------------------------------------------- Python


def parse_requirements(
    path: str, text: str, read: Reader | None = None, _seen: frozenset[str] = frozenset()
) -> list[Dependency]:
    """``requirements*.txt``, following ``-r`` and ``-c`` includes through ``read``."""
    out: list[Dependency] = []
    logical: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append((start, (buffer + line).strip()))
        buffer = ""
    for number, line in logical:
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line:
            continue
        include = re.match(r"^(?:-r|-c|--requirement|--constraint)[\s=]*(\S+)", line)
        if include:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), include[1]))
            if read is not None and target not in _seen:
                inner = read(target)
                if inner is not None:
                    out.extend(parse_requirements(target, inner, read, _seen | {path}))
            continue
        editable = line.startswith(("-e ", "--editable"))
        if line.startswith("-") and not editable:
            continue
        line = re.sub(r"^(-e|--editable)\s+", "", line)
        integrity = None
        hash_match = re.search(r"--hash=(\S+)", line)
        if hash_match:
            integrity = hash_match[1]
        line = re.sub(r"\s--\S+", "", line).split(";")[0].strip()
        if "://" in line or line.startswith((".", "/", "file:")):
            name = re.search(r"#egg=([\w.-]+)", line)
            if name:
                out.append(
                    _dep("PyPI", name[1], "", path, direct=True, line=number, declared=line[:200])
                )
            continue
        m = _REQ_NAME.match(line)
        if not m:
            continue
        spec = m[3].strip()
        pin = _PIN.match(spec)
        out.append(
            _dep(
                "PyPI",
                m[1],
                pin[1] if pin else "",
                path,
                direct=True,
                declared=spec or None,
                line=number,
                integrity=integrity,
            )
        )
    return out


def _pep508(spec: str) -> tuple[str, str] | None:
    m = _REQ_NAME.match(spec.split(";", maxsplit=1)[0].strip())
    return (m[1], m[3].strip()) if m else None


def parse_pyproject(path: str, text: str) -> list[Dependency]:
    """``pyproject.toml``: PEP 621, dependency groups and Poetry."""
    data = tomllib.loads(text)
    out: list[Dependency] = []

    def add(spec: str, scope: str) -> None:
        parsed = _pep508(spec)
        if parsed:
            name, rng = parsed
            pin = _PIN.match(rng)
            out.append(
                _dep(
                    "PyPI",
                    name,
                    pin[1] if pin else "",
                    path,
                    direct=True,
                    scope=scope,
                    declared=rng or None,
                    line=_line_of(text, name),
                )
            )

    project = data.get("project", {})
    for spec in project.get("dependencies", []):
        add(spec, "runtime")
    for group, specs in project.get("optional-dependencies", {}).items():
        for spec in specs:
            add(spec, f"optional:{group}")
    for group, specs in data.get("dependency-groups", {}).items():
        for spec in specs:
            if isinstance(spec, str):
                add(spec, f"dev:{group}")
    poetry = data.get("tool", {}).get("poetry", {})
    for name, rng in poetry.get("dependencies", {}).items():
        if name.lower() != "python":
            declared = rng if isinstance(rng, str) else rng.get("version", "")
            out.append(
                _dep(
                    "PyPI",
                    name,
                    "",
                    path,
                    direct=True,
                    declared=declared,
                    line=_line_of(text, name),
                )
            )
    for group in poetry.get("group", {}).values():
        for name, rng in group.get("dependencies", {}).items():
            declared = rng if isinstance(rng, str) else rng.get("version", "")
            out.append(_dep("PyPI", name, "", path, direct=True, scope="dev", declared=declared))
    return out


def parse_toml_lock(path: str, text: str, ecosystem: str) -> list[Dependency]:
    """``poetry.lock``, ``uv.lock`` and ``Cargo.lock`` share the ``[[package]]`` shape."""
    data = tomllib.loads(text)
    out: list[Dependency] = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        source = pkg.get("source")
        local = isinstance(source, dict) and ("editable" in source or "virtual" in source)
        deps = pkg.get("dependencies", [])
        requires = (
            [d.get("name", "") if isinstance(d, dict) else str(d).split(" ")[0] for d in deps]
            if isinstance(deps, list)
            else list(deps)
        )
        out.append(
            _dep(
                ecosystem,
                name,
                str(version),
                path,
                internal=local,
                line=_line_of(text, f'name = "{name}"'),
                requires=[r for r in requires if r],
                integrity=pkg.get("checksum"),
            )
        )
    return out


# --------------------------------------------------------------------------------- JavaScript


def parse_package_json(path: str, text: str) -> list[Dependency]:
    """``package.json`` declarations (ranges, not resolved versions)."""
    data = json.loads(text)
    out: list[Dependency] = []
    for section, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        for name, rng in (data.get(section) or {}).items():
            exact = re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][\w.]+)?", str(rng))
            out.append(
                _dep(
                    "npm",
                    name,
                    str(rng).lstrip("v") if exact else "",
                    path,
                    direct=True,
                    scope=scope,
                    declared=str(rng),
                    line=_line_of(text, f'"{name}"'),
                )
            )
    return out


def parse_package_lock(path: str, text: str) -> list[Dependency]:
    """``package-lock.json`` v1, v2 and v3; v2's legacy tree is ignored when ``packages`` exists."""
    data = json.loads(text)
    out: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or "node_modules/" not in key or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            if "version" not in meta:
                continue
            scope = "dev" if meta.get("dev") else "optional" if meta.get("optional") else "runtime"
            out.append(
                _dep(
                    "npm",
                    name,
                    meta["version"],
                    path,
                    scope=scope,
                    integrity=meta.get("integrity"),
                    line=_line_of(text, f'"{key}"'),
                    requires=list((meta.get("dependencies") or {}).keys()),
                )
            )
        return out

    def walk(tree: dict[str, Any]) -> None:
        for name, meta in tree.items():
            if "version" in meta:
                out.append(
                    _dep(
                        "npm",
                        name,
                        meta["version"],
                        path,
                        scope="dev" if meta.get("dev") else "runtime",
                        integrity=meta.get("integrity"),
                        line=_line_of(text, f'"{name}"'),
                        requires=list((meta.get("requires") or {}).keys()),
                    )
                )
            walk(meta.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return out


def parse_yarn_lock(path: str, text: str) -> list[Dependency]:
    """``yarn.lock``, classic (``version "x"``) and Berry (YAML)."""
    out: list[Dependency] = []
    if "__metadata:" in text:
        data = yaml.safe_load(text) or {}
        for key, meta in data.items():
            if key == "__metadata" or not isinstance(meta, dict):
                continue
            first = key.split(",")[0].strip().strip('"')
            name = (
                re.sub(r"@npm:.*$|@[^@]*$", "", first)
                if first.startswith("@")
                else first.split("@")[0]
            )
            if first.startswith("@"):
                name = "@" + first[1:].split("@")[0]
            out.append(
                _dep(
                    "npm",
                    name,
                    str(meta.get("version", "")),
                    path,
                    integrity=meta.get("checksum"),
                    line=_line_of(text, first),
                    requires=list((meta.get("dependencies") or {}).keys()),
                )
            )
        return out
    block = re.compile(r"^(\S.*):\n((?:[ \t]+.*\n?)+)", re.MULTILINE)
    for m in block.finditer(text):
        first = m[1].split(",")[0].strip().strip('"')
        name = ("@" + first[1:].split("@")[0]) if first.startswith("@") else first.split("@")[0]
        version = re.search(r'^\s+version\s+"?([^"\n]+)"?', m[2], re.MULTILINE)
        integrity = re.search(r"^\s+integrity\s+(\S+)", m[2], re.MULTILINE)
        if name and version:
            out.append(
                _dep(
                    "npm",
                    name,
                    version[1],
                    path,
                    integrity=integrity[1] if integrity else None,
                    line=text.count("\n", 0, m.start()) + 1,
                )
            )
    return out


def parse_pnpm_lock(path: str, text: str) -> list[Dependency]:
    """``pnpm-lock.yaml`` (v5 ``/name/ver`` and v6+ ``/name@ver`` keys)."""
    data = yaml.safe_load(text) or {}
    out: list[Dependency] = []
    for key in data.get("packages") or {}:
        k = str(key).lstrip("/")
        k = re.sub(r"\(.*\)$", "", k)
        if "@" in k[1:]:
            idx = k.rfind("@")
            name, version = k[:idx], k[idx + 1 :]
        else:
            name, _, version = k.rpartition("/")
        if name and version:
            out.append(
                _dep("npm", name, version.split("_")[0], path, line=_line_of(text, str(key)))
            )
    return out


# --------------------------------------------------------------------------------- Java, Go, ...


def parse_pom(path: str, text: str) -> list[Dependency]:
    """``pom.xml`` with ``${property}`` and parent version resolution."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("pom.xml with a DTD is refused")
    import xml.etree.ElementTree as ET  # noqa: PLC0415 - DTDs refused above

    root = ET.fromstring(text)  # noqa: S314
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def child(node: Any, tag: str) -> str | None:
        found = node.find(f"{ns}{tag}")
        return found.text.strip() if found is not None and found.text else None

    props: dict[str, str] = {}
    properties = root.find(f"{ns}properties")
    if properties is not None:
        for p in properties:
            props[p.tag.replace(ns, "")] = (p.text or "").strip()
    parent = root.find(f"{ns}parent")
    for tag in ("groupId", "artifactId", "version"):
        value = child(root, tag) or (child(parent, tag) if parent is not None else None)
        if value:
            props[f"project.{tag}"] = value
            props[f"pom.{tag}"] = value

    def resolve(value: str | None) -> str:
        if not value:
            return ""
        for _ in range(5):
            value = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m[1], m[0]), value)
        return value

    managed: dict[str, str] = {}
    for dep in root.findall(f"{ns}dependencyManagement/{ns}dependencies/{ns}dependency"):
        managed[f"{child(dep, 'groupId')}:{child(dep, 'artifactId')}"] = resolve(
            child(dep, "version")
        )
    out: list[Dependency] = []
    for dep in root.findall(f"{ns}dependencies/{ns}dependency"):
        group, artefact = resolve(child(dep, "groupId")), resolve(child(dep, "artifactId"))
        version = resolve(child(dep, "version")) or managed.get(f"{group}:{artefact}", "")
        if "${" in version:
            version = ""
        out.append(
            _dep(
                "Maven",
                f"{group}:{artefact}",
                version,
                path,
                direct=True,
                scope=child(dep, "scope") or "runtime",
                line=_line_of(text, f"<artifactId>{artefact}</artifactId>"),
            )
        )
    return out


def parse_gradle(path: str, text: str) -> list[Dependency]:
    """``build.gradle(.kts)`` string-notation dependencies."""
    out: list[Dependency] = []
    pattern = re.compile(
        r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|annotationProcessor)"
        r"""\s*\(?\s*['"]([\w.-]+):([\w.-]+):([\w.\-+]+)['"]"""
    )
    for m in pattern.finditer(text):
        scope = "test" if m[1].startswith("test") else "runtime"
        out.append(
            _dep(
                "Maven", f"{m[2]}:{m[3]}", m[4], path, direct=True, scope=scope,
                line=text.count("\n", 0, m.start()) + 1,
            )
        )  # fmt: skip
    return out


def parse_go_mod(path: str, text: str) -> list[Dependency]:
    """``go.mod`` requirements (``// indirect`` marks transitive ones)."""
    out: list[Dependency] = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = line[len("require ") :] if line.startswith("require ") else line if in_block else ""
        m = re.match(r"^(\S+)\s+(v\S+)(.*)$", body)
        if m:
            out.append(_dep("Go", m[1], m[2], path, direct="// indirect" not in m[3], line=number))
    return out


def parse_go_sum(path: str, text: str) -> list[Dependency]:
    """``go.sum``: one component per module version (the ``/go.mod`` hashes are skipped)."""
    seen: dict[tuple[str, str], Dependency] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            seen[(parts[0], parts[1])] = _dep(
                "Go", parts[0], parts[1], path, integrity=parts[2], line=number
            )
    return list(seen.values())


def parse_gemfile_lock(path: str, text: str) -> list[Dependency]:
    """``Gemfile.lock`` ``specs:`` entries."""
    out: list[Dependency] = []
    in_specs = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^    (\S+) \(([^)]+)\)$", line)
        if in_specs and m:
            out.append(_dep("RubyGems", m[1], m[2].split("-")[0], path, line=number))
    return out


def parse_composer_lock(path: str, text: str) -> list[Dependency]:
    """``composer.lock`` packages and dev packages."""
    data = json.loads(text)
    out: list[Dependency] = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for pkg in data.get(section, []):
            out.append(
                _dep(
                    "Packagist", pkg["name"], str(pkg["version"]).lstrip("v"), path, scope=scope,
                    line=_line_of(text, f'"{pkg["name"]}"'),
                    requires=[r for r in (pkg.get("require") or {}) if r != "php"],
                )
            )  # fmt: skip
    return out


def parse_manifest(path: str, text: str, read: Reader | None = None) -> list[Dependency]:
    """The components of one manifest or lock file; ``ValueError`` when it is not parseable."""
    name = posixpath.basename(path)
    try:
        if REQUIREMENT_FILE.match(name):
            return parse_requirements(path, text, read)
        table: dict[str, Callable[[], list[Dependency]]] = {
            "pyproject.toml": lambda: parse_pyproject(path, text),
            "poetry.lock": lambda: parse_toml_lock(path, text, "PyPI"),
            "uv.lock": lambda: parse_toml_lock(path, text, "PyPI"),
            "Cargo.lock": lambda: parse_toml_lock(path, text, "crates.io"),
            "package.json": lambda: parse_package_json(path, text),
            "package-lock.json": lambda: parse_package_lock(path, text),
            "yarn.lock": lambda: parse_yarn_lock(path, text),
            "pnpm-lock.yaml": lambda: parse_pnpm_lock(path, text),
            "pom.xml": lambda: parse_pom(path, text),
            "build.gradle": lambda: parse_gradle(path, text),
            "build.gradle.kts": lambda: parse_gradle(path, text),
            "go.mod": lambda: parse_go_mod(path, text),
            "go.sum": lambda: parse_go_sum(path, text),
            "Gemfile.lock": lambda: parse_gemfile_lock(path, text),
            "composer.lock": lambda: parse_composer_lock(path, text),
        }
        parser = table.get(name)
        return parser() if parser else []
    except (ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as error:
        raise ValueError(f"{path}: {type(error).__name__}") from None
    except Exception as error:  # noqa: BLE001 - tomllib / ElementTree errors
        raise ValueError(f"{path}: {type(error).__name__}") from None


# --------------------------------------------------------------------------------- graph


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def build_graph(files: dict[str, str]) -> tuple[DependencyGraph, list[str]]:
    """The inventory of ``files`` (path to text), and the paths that could not be parsed."""
    by_dir: dict[str, list[tuple[str, list[Dependency]]]] = {}
    failed: list[str] = []
    for path in sorted(files):
        if not is_manifest_path(path):
            continue
        try:
            parsed = parse_manifest(path, files[path], files.get)
        except ValueError:
            failed.append(path)
            continue
        by_dir.setdefault(posixpath.dirname(path), []).append((path, parsed))
    merged: dict[str, Dependency] = {}
    manifests: list[str] = []
    for entries in by_dir.values():
        eco_has_lock: set[str] = set()
        for path, deps in entries:
            if posixpath.basename(path) in LOCK_NAMES and deps:
                eco_has_lock.add(deps[0].ecosystem)
        declared: dict[tuple[str, str], Dependency] = {}
        for path, deps in entries:
            manifests.append(path)
            is_lock = posixpath.basename(path) in LOCK_NAMES
            for dep in deps:
                key = (dep.ecosystem, _norm(dep.name))
                if is_lock:
                    merged.setdefault(f"{path}|{dep.purl}", dep)
                elif dep.ecosystem in eco_has_lock:
                    declared[key] = dep
                else:
                    merged.setdefault(f"{path}|{dep.purl}|{dep.declared_range}", dep)
        if declared:
            for key_, dep in list(merged.items()):
                found = declared.get((dep.ecosystem, _norm(dep.name)))
                if found is not None and posixpath.dirname(dep.resolved_from) == posixpath.dirname(
                    found.resolved_from
                ):
                    merged[key_] = dep.evolve(
                        direct=True,
                        scope=found.scope,
                        declared_range=found.declared_range,
                        locations=(dep.resolved_from, found.resolved_from),
                    )
    ordered = tuple(
        sorted(merged.values(), key=lambda d: (d.ecosystem, d.name, d.version, d.resolved_from))
    )
    index: dict[tuple[str, str], list[str]] = {}
    for d in ordered:
        index.setdefault((d.ecosystem, _norm(d.name)), []).append(d.purl)
    edges = tuple(
        sorted(
            {
                (d.purl, target)
                for d in ordered
                for req in d.requires
                for target in index.get((d.ecosystem, _norm(req)), [])[:1]
            }
        )
    )
    return DependencyGraph(dependencies=ordered, edges=edges, manifests=tuple(manifests)), failed
