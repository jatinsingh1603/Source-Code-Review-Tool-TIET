"""External secret engines: output parsing, mapping, invocation controls and union (E08-04).

No engine is installed: a fake runner returns recorded-shape reports for the staged files and
captures what the adapter asked for.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.overlap import resolve_overlaps
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.secrets import adapters
from codekavach.privacy.detect.secrets.adapters import (
    DETECT_SECRETS_TYPES,
    GITLEAKS_RULES,
    AdapterError,
    DetectSecretsEngine,
    EngineScan,
    ExternalFindingsDetector,
    GitleaksEngine,
    RunResult,
    RunSpec,
    engine_environment,
    staged_copy,
    subprocess_runner,
)
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from codekavach.privacy.detect.vocabulary import SECRET_SUBTYPES
from tests.support.synthetic import example_secret

AWS = example_secret("aws_access_key")
GITHUB = example_secret("github_token")
SOURCE = f'aws_key = "{AWS}"\nother = 1\ntoken = "{GITHUB}"\n'


class FakeRunner:
    """Records every call and answers with a report built from the staged tree."""

    def __init__(self, make_report: object = None, returncode: int = 0) -> None:
        self.calls: list[RunSpec] = []
        self.seen_read_only: list[bool] = []
        self.staged_names: list[str] = []
        self._make_report = make_report
        self._returncode = returncode

    def __call__(self, spec: RunSpec) -> RunResult:
        self.calls.append(spec)
        files = sorted(p for p in spec.cwd.joinpath("tree").rglob("*") if p.is_file())
        self.seen_read_only.append(all(not os.access(p, os.W_OK) for p in files))
        self.staged_names.extend(p.name for p in files)
        body = b"[]"
        if callable(self._make_report):
            body = self._make_report(spec, files)
        return RunResult(self._returncode, body)


def write(root: Path, name: str, text: str = SOURCE) -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode("utf-8"))


def gitleaks(rule: str, secret: str, first: int = 1, last: int | None = None) -> object:
    def report(spec: RunSpec, files: list[Path]) -> bytes:
        entry = {
            "RuleID": rule,
            "StartLine": first,
            "EndLine": last or first,
            "Secret": secret,
            "File": str(files[0]),
        }
        return json.dumps([entry]).encode("utf-8")

    return report


def scan_gitleaks(tmp_path: Path, make_report: object, text: str = SOURCE) -> EngineScan:
    write(tmp_path, "src/app.py", text)
    engine = GitleaksEngine(executable="gitleaks", runner=FakeRunner(make_report))
    return engine.scan(["src/app.py"], workdir=tmp_path)


# --- gitleaks output ---------------------------------------------------------------------


def test_a_gitleaks_finding_becomes_a_span_over_exactly_the_secret(tmp_path: Path) -> None:
    result = scan_gitleaks(tmp_path, gitleaks("aws-access-token", AWS))
    (found,) = result.spans["src/app.py"]
    start = SOURCE.encode().index(AWS.encode())
    assert (found.start_byte, found.end_byte) == (start, start + len(AWS))
    assert (found.subtype, found.confidence) == ("aws_access_key", Confidence.MEDIUM)
    assert found.detector == "secret.gitleaks"
    assert result.unmapped == 0 and result.located_by_line == 0


def test_an_unmapped_rule_is_a_low_generic_credential_and_is_counted(tmp_path: Path) -> None:
    result = scan_gitleaks(tmp_path, gitleaks("some-new-vendor-token", AWS))
    (found,) = result.spans["src/app.py"]
    assert (found.subtype, found.confidence) == ("generic_credential", Confidence.LOW)
    assert result.unmapped == 1


def test_a_secret_that_is_not_on_its_line_falls_back_to_the_whole_line(tmp_path: Path) -> None:
    result = scan_gitleaks(tmp_path, gitleaks("aws-access-token", "not-on-the-line"))
    (found,) = result.spans["src/app.py"]
    line = f'aws_key = "{AWS}"'.encode()
    assert (found.start_byte, found.end_byte) == (0, len(line))
    assert found.confidence is Confidence.LOW
    assert result.located_by_line == 1


def test_a_multi_line_secret_is_located_across_lines(tmp_path: Path) -> None:
    fence = "-" * 5
    label = "PRIVATE " + "KEY"
    body = f"{fence}BEGIN {label}{fence}\nQUJDREVGRw\n{fence}END {label}{fence}"
    text = f"key = '''\n{body}\n'''\n"
    result = scan_gitleaks(tmp_path, gitleaks("private-key", body, first=2, last=4), text)
    (found,) = result.spans["src/app.py"]
    assert text.encode()[found.start_byte : found.end_byte] == body.encode()
    assert found.subtype == "private_key_block"


def test_spans_are_byte_offsets_for_multibyte_text(tmp_path: Path) -> None:
    text = f'naam = "नमस्ते"; key = "{AWS}"\n'
    result = scan_gitleaks(tmp_path, gitleaks("aws-access-token", AWS), text)
    (found,) = result.spans["src/app.py"]
    assert text.encode()[found.start_byte : found.end_byte] == AWS.encode()


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"{}", b'"text"', b"[1]", b'[{"RuleID": "x"}]', b'[{"RuleID": 3}]'],
)
def test_malformed_gitleaks_output_raises_instead_of_returning_spans(
    tmp_path: Path, raw: bytes
) -> None:
    with pytest.raises(AdapterError):
        scan_gitleaks(tmp_path, lambda spec, files: raw)


def test_one_bad_entry_discards_the_whole_report(tmp_path: Path) -> None:
    def report(spec: RunSpec, files: list[Path]) -> bytes:
        good = {"RuleID": "jwt", "StartLine": 1, "EndLine": 1, "Secret": AWS, "File": str(files[0])}
        return json.dumps([good, {"RuleID": "jwt"}]).encode()

    with pytest.raises(AdapterError):
        scan_gitleaks(tmp_path, report)


def test_an_error_message_never_quotes_the_output(tmp_path: Path) -> None:
    with pytest.raises(AdapterError) as caught:
        scan_gitleaks(tmp_path, lambda spec, files: AWS.encode())
    assert AWS not in str(caught.value)


def test_a_report_for_a_file_that_was_not_staged_is_ignored(tmp_path: Path) -> None:
    def report(spec: RunSpec, files: list[Path]) -> bytes:
        entry = {"RuleID": "jwt", "StartLine": 1, "EndLine": 1, "Secret": AWS, "File": "/etc/x"}
        return json.dumps([entry]).encode()

    assert scan_gitleaks(tmp_path, report).spans == {}


# --- detect-secrets output ---------------------------------------------------------------


def detect_secrets_report(kind: str, secret: str, line: int = 1) -> object:
    def report(spec: RunSpec, files: list[Path]) -> bytes:
        digest = hashlib.sha1(secret.encode(), usedforsecurity=False).hexdigest()
        entry = {"type": kind, "hashed_secret": digest, "line_number": line, "is_verified": False}
        return json.dumps({"results": {str(files[0]): [entry]}}).encode()

    return report


def scan_detect_secrets(tmp_path: Path, make_report: object, text: str = SOURCE) -> EngineScan:
    write(tmp_path, "src/app.py", text)
    engine = DetectSecretsEngine(executable="detect-secrets", runner=FakeRunner(make_report))
    return engine.scan(["src/app.py"], workdir=tmp_path)


def test_detect_secrets_locates_the_secret_by_its_hash(tmp_path: Path) -> None:
    result = scan_detect_secrets(tmp_path, detect_secrets_report("AWS Access Key", AWS))
    (found,) = result.spans["src/app.py"]
    start = SOURCE.encode().index(AWS.encode())
    assert (found.start_byte, found.end_byte) == (start, start + len(AWS))
    assert (found.subtype, found.confidence) == ("aws_access_key", Confidence.MEDIUM)
    assert found.detector == "secret.detect_secrets"
    assert result.located_by_line == 0


def test_detect_secrets_finds_a_secret_inside_a_url(tmp_path: Path) -> None:
    # pragma: allowlist nextline secret
    text = "url = 'https://user:Zx9fKq2LmPw@host.example/db'\n"
    result = scan_detect_secrets(
        tmp_path, detect_secrets_report("Basic Auth Credentials", "Zx9fKq2LmPw"), text
    )
    (found,) = result.spans["src/app.py"]
    assert text.encode()[found.start_byte : found.end_byte] == b"Zx9fKq2LmPw"


def test_detect_secrets_falls_back_to_the_line_when_no_substring_has_the_hash(
    tmp_path: Path,
) -> None:
    result = scan_detect_secrets(tmp_path, detect_secrets_report("Secret Keyword", "elsewhere"))
    (found,) = result.spans["src/app.py"]
    assert found.confidence is Confidence.LOW
    assert result.located_by_line == 1


def test_an_unknown_detect_secrets_type_is_a_low_generic_credential(tmp_path: Path) -> None:
    result = scan_detect_secrets(tmp_path, detect_secrets_report("Brand New Detector", AWS))
    (found,) = result.spans["src/app.py"]
    assert (found.subtype, found.confidence) == ("generic_credential", Confidence.LOW)
    assert result.unmapped == 1


@pytest.mark.parametrize(
    "raw",
    [b"nope", b"[]", b'{"results": []}', b'{"results": {}, "x": ['],
)
def test_malformed_detect_secrets_output_raises(tmp_path: Path, raw: bytes) -> None:
    write(tmp_path, "src/app.py")
    engine = DetectSecretsEngine(executable="x", runner=FakeRunner(lambda spec, files: raw))
    with pytest.raises(AdapterError):
        engine.scan(["src/app.py"], workdir=tmp_path)


# --- the tables --------------------------------------------------------------------------


@pytest.mark.parametrize("table", [GITLEAKS_RULES, DETECT_SECRETS_TYPES], ids=["gitleaks", "ds"])
def test_every_mapped_rule_names_a_subtype_of_the_vocabulary(table: dict[str, str]) -> None:
    assert set(table.values()) <= SECRET_SUBTYPES


# --- how the engines are invoked ---------------------------------------------------------


def test_gitleaks_is_invoked_with_validation_off_no_config_and_a_private_environment(
    tmp_path: Path,
) -> None:
    write(tmp_path, "src/app.py")
    runner = FakeRunner()
    environ = {
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "x",
        "HTTPS_PROXY": "http://proxy",
        "AWS_ACCESS_KEY_ID": "y",
        "GITLEAKS_CONFIG": "/repo/.gitleaks.toml",
    }
    GitleaksEngine(executable="/bin/gitleaks", runner=runner, environ=environ).scan(
        ["src/app.py"], workdir=tmp_path
    )
    (call,) = runner.calls
    argv = call.argv
    assert argv[0] == "/bin/gitleaks" and argv[1] == "dir"
    assert "--ignore-gitleaks-allow" in argv
    assert argv[argv.index("--report-path") + 1] == "-"
    assert not any(arg.startswith(("--config", "-c", "--validation")) for arg in argv)
    assert not any(tmp_path.as_posix() in arg.replace("\\", "/") for arg in argv)
    assert set(call.env) <= {
        "PATH", "SYSTEMROOT", "LANG", "LC_ALL", "HOME", "USERPROFILE", "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME", "NO_COLOR", "NO_PROXY", "GOMEMLIMIT",
    }  # fmt: skip
    assert call.env["PATH"] == "/usr/bin"
    assert call.env["NO_PROXY"] == "*"
    assert call.timeout_seconds == 120.0
    assert call.cwd != tmp_path and tmp_path not in call.cwd.parents
    assert runner.seen_read_only == [True]


def test_detect_secrets_is_invoked_without_verification_or_a_baseline(tmp_path: Path) -> None:
    write(tmp_path, "src/app.py")
    runner = FakeRunner(lambda spec, files: b'{"results": {}}')
    DetectSecretsEngine(executable="/bin/ds", runner=runner, environ={}).scan(
        ["src/app.py"], workdir=tmp_path
    )
    (call,) = runner.calls
    assert call.argv[1:4] == ("scan", "--all-files", "--no-verify")
    assert not any("baseline" in arg for arg in call.argv)
    assert call.address_space_limit_bytes == 2 * 1024**3
    assert runner.seen_read_only == [True]


def test_the_timeout_is_configurable_and_passed_on(tmp_path: Path) -> None:
    write(tmp_path, "a.py")
    runner = FakeRunner()
    GitleaksEngine(executable="g", runner=runner, timeout_seconds=7.5).scan(
        ["a.py"], workdir=tmp_path
    )
    assert runner.calls[0].timeout_seconds == 7.5


def test_engine_environment_drops_everything_but_the_allow_list(tmp_path: Path) -> None:
    env = engine_environment({"PATH": "p", "HOME": "/real", "SECRET_X": "s"}, tmp_path)
    assert env["HOME"] == str(tmp_path) and "SECRET_X" not in env


def test_a_nonzero_exit_status_raises(tmp_path: Path) -> None:
    write(tmp_path, "a.py")
    engine = GitleaksEngine(executable="g", runner=FakeRunner(returncode=2))
    with pytest.raises(AdapterError, match="status 2"):
        engine.scan(["a.py"], workdir=tmp_path)


def test_a_missing_executable_raises_and_available_is_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    write(tmp_path, "a.py")
    engine = GitleaksEngine(runner=FakeRunner())
    assert engine.available() is False
    with pytest.raises(AdapterError, match="not installed"):
        engine.scan(["a.py"], workdir=tmp_path)


def test_the_real_runner_maps_a_timeout_to_adapter_error(tmp_path: Path) -> None:
    spec = RunSpec(
        (sys.executable, "-c", "import time; time.sleep(5)"), dict(os.environ), tmp_path, 0.3
    )
    with pytest.raises(AdapterError, match="timeout"):
        subprocess_runner(spec)


def test_the_real_runner_does_not_start_a_shell_or_pass_other_environment(tmp_path: Path) -> None:
    code = "import os,sys; sys.stdout.write(','.join(sorted(os.environ)))"
    spec = RunSpec((sys.executable, "-c", code), {"ONLY": "1", **_system_env()}, tmp_path, 20.0)
    names = subprocess_runner(spec).stdout.decode().split(",")
    assert "ONLY" in names and "GITHUB_TOKEN" not in names


def _system_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in {"SYSTEMROOT", "PATH"}}


def test_the_real_runner_reports_a_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="could not be started"):
        subprocess_runner(RunSpec(("definitely-not-a-binary-xyz",), {}, tmp_path, 5.0))


def test_the_subprocess_module_is_called_without_a_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, 0, b"[]", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    subprocess_runner(RunSpec(("tool", "x"), {"A": "b"}, tmp_path, 3.0))
    assert captured["env"] == {"A": "b"}
    assert captured.get("shell") in (None, False)
    assert captured["stdin"] == subprocess.DEVNULL


# --- staging -----------------------------------------------------------------------------


def test_repository_supplied_engine_configuration_is_never_staged(tmp_path: Path) -> None:
    for name in (".gitleaks.toml", ".secrets.baseline", "sub/.gitleaksignore", "src/app.py"):
        write(tmp_path, name, "x = 1\n")
    with staged_copy(
        [".gitleaks.toml", ".secrets.baseline", "sub/.gitleaksignore", "src/app.py"], tmp_path
    ) as staged:
        assert sorted(staged.files) == ["src/app.py"]
        assert staged.skipped == 3
        names = {p.name for p in (staged.root / "tree").rglob("*")}
    assert ".gitleaks.toml" not in names


def test_paths_that_escape_the_work_directory_or_are_too_large_are_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("x\n")
    work = tmp_path / "work"
    write(work, "ok.py", "y = 1\n")
    write(work, "big.py", "z" * 100)
    monkeypatch.setattr(adapters, "MAX_FILE_BYTES", 50)
    with staged_copy(
        ["../outside.py", "/abs/path.py", "ok.py", "big.py", "gone.py"], work
    ) as staged:
        assert sorted(staged.files) == ["ok.py"]
        assert staged.skipped == 4


def test_a_symbolic_link_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("hidden\n")
    work = tmp_path / "work"
    work.mkdir()
    try:
        (work / "link.py").symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available here")
    with staged_copy(["link.py"], work) as staged:
        assert staged.files == {}


def test_the_staged_tree_is_removed_afterwards_even_though_it_was_read_only(
    tmp_path: Path,
) -> None:
    write(tmp_path, "a/b.py")
    with staged_copy(["a/b.py"], tmp_path) as staged:
        root = staged.root
        assert root.exists()
    assert not root.exists()


def test_the_work_directory_is_not_modified(tmp_path: Path) -> None:
    write(tmp_path, "src/app.py")
    before = sorted(p.name for p in tmp_path.rglob("*"))
    scan_gitleaks(tmp_path, gitleaks("aws-access-token", AWS))
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_nothing_is_run_when_nothing_could_be_staged(tmp_path: Path) -> None:
    runner = FakeRunner()
    result = GitleaksEngine(executable="g", runner=runner).scan(["missing.py"], workdir=tmp_path)
    assert runner.calls == [] and result.skipped_files == 1


# --- union with the native detectors -----------------------------------------------------


def settings() -> Settings:
    return Settings.model_validate({})


def registry_with(scan: EngineScan) -> DetectorRegistry:
    registry = register_secret_detectors(DetectorRegistry())
    registry.register(ExternalFindingsDetector(scan))
    return registry


def run(text: str, registry: DetectorRegistry) -> tuple[TypedSpan, ...]:
    return detect_all(
        RawCode(text),
        path="src/app.py",
        language=Language.PYTHON,
        settings=settings(),
        registry=registry,
    )


def test_an_external_span_is_unioned_by_resolve_overlaps(tmp_path: Path) -> None:
    text = f'plain = "{AWS}"\nnote = "cl1ent-s3cret-v@lue"\n'
    unknown = "cl1ent-s3cret-v@lue"
    result = scan_gitleaks(tmp_path, gitleaks("vendor-x", unknown, first=2), text)
    native = run(text, register_secret_detectors(DetectorRegistry()))
    merged = run(text, registry_with(result))
    start = text.encode().index(unknown.encode())
    assert any(s.start_byte <= start and s.end_byte >= start + len(unknown) for s in merged)
    assert not any(s.start_byte <= start < s.end_byte for s in native)
    # whatever the native detectors found is still found
    covered = {b for s in merged for b in range(s.start_byte, s.end_byte)}
    assert {b for s in native for b in range(s.start_byte, s.end_byte)} <= covered


def test_the_detector_gives_no_spans_for_a_text_of_another_length(tmp_path: Path) -> None:
    result = scan_gitleaks(tmp_path, gitleaks("aws-access-token", AWS))
    detector = ExternalFindingsDetector(result)
    full = detector.detect(RawCode(SOURCE), path="src/app.py", language=Language.PYTHON)
    sliced = detector.detect(RawCode(SOURCE[:20]), path="src/app.py", language=Language.PYTHON)
    other = detector.detect(RawCode(SOURCE), path="src/other.py", language=Language.PYTHON)
    assert len(full) == 1 and sliced == () and other == ()


SPAN_STARTS = st.integers(min_value=0, max_value=60)


@st.composite
def spans(draw: st.DrawFn, confidences: tuple[Confidence, ...], detector: str) -> TypedSpan:
    start = draw(SPAN_STARTS)
    length = draw(st.integers(min_value=1, max_value=30))
    kind = draw(st.sampled_from([PlaceholderKind.SECRET, PlaceholderKind.PII]))
    subtype = (
        "email"
        if kind is PlaceholderKind.PII
        else draw(st.sampled_from(["aws_access_key", "github_token", "generic_credential"]))
    )
    return TypedSpan(
        kind=kind,
        subtype=subtype,
        start_byte=start,
        end_byte=start + length,
        confidence=draw(st.sampled_from(confidences)),
        detector=detector,
    )


def covered(items: list[TypedSpan]) -> set[int]:
    return {b for s in items for b in range(s.start_byte, s.end_byte)}


@given(
    st.lists(spans((Confidence.HIGH,), "native.high"), max_size=6),
    st.lists(spans((Confidence.LOW, Confidence.MEDIUM), "secret.gitleaks"), max_size=6),
)
def test_merging_external_spans_never_uncovers_a_native_high_byte(
    native_high: list[TypedSpan], external: list[TypedSpan]
) -> None:
    merged = resolve_overlaps([*native_high, *external])
    assert covered(native_high) <= covered(list(merged))
