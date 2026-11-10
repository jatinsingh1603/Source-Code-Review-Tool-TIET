"""``GitSource``: the argument vector, the environment, URL checks and clean-up (E06-03).

A fake runner stands in for git, so no test here starts a process or opens a socket; the real
clones are in ``tests/integration/ingest/test_git_clone.py``.
"""

import base64
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import UnsafeArchiveEntry, UnsupportedSource
from codekavach.ingest.sources.git import (
    HARDENING,
    GitResult,
    GitSource,
    check_git_url,
    check_ref,
    check_tree,
    hardened_environment,
    looks_like_git_target,
)

URL = "https://git.example.invalid/team/app.git"
TOKEN = "tok-123-not-a-real-token"  # pragma: allowlist secret


def limits(**overrides: object) -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings(**overrides))  # type: ignore[arg-type]


class Recorder:
    """A fake runner: records every call and clones nothing unless told to write files."""

    def __init__(
        self, *, results: Sequence[int] = (), files: Mapping[str, str] | None = None
    ) -> None:
        self.calls: list[tuple[list[str], dict[str, str], Path | None]] = []
        self._results = list(results)
        self._files = files or {}

    def __call__(
        self, argv: Sequence[str], env: Mapping[str, str], cwd: Path | None, timeout: float
    ) -> GitResult:
        self.calls.append((list(argv), dict(env), cwd))
        if argv[len(HARDENING) + 1] == "clone":
            into = Path(argv[-1])
            for name, content in self._files.items():
                (into / name).parent.mkdir(parents=True, exist_ok=True)
                (into / name).write_text(content, encoding="utf-8")
        return GitResult(self._results.pop(0) if self._results else 0)


def clone(tmp_path: Path, recorder: Recorder, **options: object) -> Path:
    source = GitSource(runner=recorder, executable="git", environ={"PATH": "/bin"}, **options)  # type: ignore[arg-type]
    return source.materialise(URL, limits=limits(), into=tmp_path / "work" / "tree")


def test_the_clone_carries_every_hardening_switch(tmp_path: Path) -> None:
    recorder = Recorder()
    clone(tmp_path, recorder)
    argv, env, _ = recorder.calls[0]
    joined = " ".join(argv)
    for flag in (
        "--no-optional-locks",
        "core.hooksPath=/dev/null",
        "core.symlinks=false",
        "protocol.ext.allow=never",
        "advice.detachedHead=false",
        "core.fsmonitor=false",
        "--no-recurse-submodules",
    ):
        assert flag in joined, flag
    assert argv[argv.index("--depth") + 1] == "1"
    assert argv[-3:-2] == ["--"]
    assert argv[-2] == URL
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert env["GIT_ALLOW_PROTOCOL"] == "https:ssh:file"
    assert "BatchMode=yes" in env["GIT_SSH_COMMAND"]


def test_the_hardening_comes_before_the_subcommand(tmp_path: Path) -> None:
    recorder = Recorder()
    clone(tmp_path, recorder)
    argv = recorder.calls[0][0]
    assert argv[1 : 1 + len(HARDENING)] == list(HARDENING)
    assert argv[1 + len(HARDENING)] == "clone"


def test_a_ref_selects_a_branch_or_tag_and_the_depth_is_passed(tmp_path: Path) -> None:
    recorder = Recorder()
    clone(tmp_path, recorder, ref="v1.2", depth=5)
    argv = recorder.calls[0][0]
    assert argv[argv.index("--branch") + 1] == "v1.2"
    assert argv[argv.index("--depth") + 1] == "5"


def test_a_commit_ref_is_fetched_and_checked_out(tmp_path: Path) -> None:
    sha = "a" * 40
    recorder = Recorder()
    clone(tmp_path, recorder, ref=sha)
    subcommands = [call[0][1 + len(HARDENING)] for call in recorder.calls]
    assert subcommands == ["clone", "fetch", "checkout"]
    assert "--no-checkout" in recorder.calls[0][0]
    assert "--branch" not in recorder.calls[0][0]


def test_the_credential_reaches_git_through_the_environment_and_never_the_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CK_TEST_GIT_TOKEN", TOKEN)
    recorder = Recorder()
    source = GitSource(
        runner=recorder,
        executable="git",
        credential="env:CK_TEST_GIT_TOKEN",
        environ={"PATH": "/bin", "CK_TEST_GIT_TOKEN": TOKEN},
    )
    source.materialise(URL, limits=limits(), into=tmp_path / "work" / "tree")
    argv, env, _ = recorder.calls[0]
    assert TOKEN not in " ".join(argv)
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    header = env["GIT_CONFIG_VALUE_0"]
    assert header.startswith("Authorization: Basic ")
    assert base64.b64decode(header.rsplit(" ", 1)[1]).decode().endswith(TOKEN)


def test_an_ssh_remote_gets_no_credential_header(tmp_path: Path) -> None:
    recorder = Recorder()
    source = GitSource(
        runner=recorder,
        executable="git",
        credential="env:CK_TEST_GIT_TOKEN",
        environ={"PATH": "/bin", "CK_TEST_GIT_TOKEN": TOKEN},
    )
    source.materialise("ssh://git@git.example.invalid/x.git", limits=limits(), into=tmp_path / "t")
    assert "GIT_CONFIG_COUNT" not in recorder.calls[0][1]


def test_the_child_environment_is_an_allow_list() -> None:
    env = hardened_environment(
        {"PATH": "/bin", "GIT_DIR": "/elsewhere", "GIT_EXEC_PATH": "/x", "FOO": "1"}
    )
    assert "GIT_DIR" not in env and "GIT_EXEC_PATH" not in env and "FOO" not in env
    assert env["PATH"] == "/bin"


def test_a_failed_clone_is_unsupported_and_leaves_no_working_root(tmp_path: Path) -> None:
    recorder = Recorder(results=[128])
    with pytest.raises(UnsupportedSource) as raised:
        clone(tmp_path, recorder)
    assert "example.invalid" not in str(raised.value)
    assert not (tmp_path / "work" / "tree").exists()


def test_a_clone_over_the_file_budget_is_removed(tmp_path: Path) -> None:
    recorder = Recorder(files={f"f{i}.py": "x" for i in range(5)})
    source = GitSource(runner=recorder, executable="git", environ={})
    with pytest.raises(LimitExceededError) as raised:
        source.materialise(URL, limits=limits(max_files=3), into=tmp_path / "w" / "tree")
    assert raised.value.kind is LimitKind.FILE_COUNT
    assert not (tmp_path / "w" / "tree").exists()


def test_a_clone_over_the_byte_budget_is_removed(tmp_path: Path) -> None:
    recorder = Recorder(files={"big.py": "x" * 5000})
    source = GitSource(runner=recorder, executable="git", environ={})
    with pytest.raises(LimitExceededError) as raised:
        source.materialise(URL, limits=limits(max_total_bytes=1000), into=tmp_path / "w" / "tree")
    assert raised.value.kind is LimitKind.TOTAL_BYTES
    assert not (tmp_path / "w" / "tree").exists()


def test_the_git_directory_is_not_counted_against_the_budgets(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / ".git").mkdir(parents=True)
    for index in range(50):
        (root / ".git" / f"o{index}").write_text("x" * 100, encoding="utf-8")
    (root / "a.py").write_text("x", encoding="utf-8")
    check_tree(root, limits(max_files=2, max_total_bytes=100))


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="no symlinks")
def test_a_link_that_leaves_the_tree_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "tree"
    root.mkdir()
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    with pytest.raises(UnsafeArchiveEntry):
        check_tree(root, limits())


def test_an_existing_non_empty_working_root_is_refused(tmp_path: Path) -> None:
    into = tmp_path / "tree"
    into.mkdir()
    (into / "old.txt").write_text("x", encoding="utf-8")
    with pytest.raises(UnsupportedSource):
        GitSource(runner=Recorder(), executable="git", environ={}).materialise(
            URL, limits=limits(), into=into
        )
    assert (into / "old.txt").exists()  # not ours to delete


@pytest.mark.parametrize(
    "target",
    [
        "--upload-pack=touch /tmp/x",
        "-oProxyCommand=evil",
        "ext::sh -c 'touch /tmp/pwned'",
        "ext::git-remote-evil",
        "fd::17",
        "http://git.example.invalid/x.git",
        "git://git.example.invalid/x.git",
        "ftp://git.example.invalid/x.git",
        "https://user:hunter2@git.example.invalid/x.git",  # pragma: allowlist secret
        "https://git.example.invalid/x .git",
        "https://git.example.invalid/x\n.git",
        "",
    ],
)
def test_a_dangerous_or_credentialed_url_is_refused_without_echoing_it(target: str) -> None:
    with pytest.raises(UnsupportedSource) as raised:
        check_git_url(target)
    assert "hunter2" not in str(raised.value)
    assert "example.invalid" not in str(raised.value)


@pytest.mark.parametrize(
    "target",
    [
        URL,
        "ssh://git@git.example.invalid/team/app.git",
        "git@git.example.invalid:team/app.git",
        "file:///srv/repos/app.git",
        "/srv/repos/app.git",
    ],
)
def test_the_accepted_url_forms_pass(target: str) -> None:
    assert check_git_url(target) == target
    assert looks_like_git_target(target)


@pytest.mark.parametrize(
    "ref", ["-x", "--upload-pack=x", "a..b", "a b", "", "x" * 300, "a/", "b.lock"]
)
def test_a_ref_must_be_a_plain_name(ref: str) -> None:
    with pytest.raises(UnsupportedSource):
        check_ref(ref)


@pytest.mark.parametrize("ref", ["main", "v1.2.3", "feature/x-y", "release/2026.11", "a" * 40])
def test_plain_refs_pass(ref: str) -> None:
    assert check_ref(ref) == ref


@pytest.mark.parametrize("depth", [0, -1, 2_000_000])
def test_a_depth_out_of_range_is_refused(depth: int) -> None:
    with pytest.raises(UnsupportedSource):
        GitSource(depth=depth)
