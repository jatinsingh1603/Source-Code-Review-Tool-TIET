"""Synthetic secret-shaped values for tests: the one audited home for them.

Rules (AGENTS.md section 3):

- The only contiguous secret-shaped literals are the two AWS documentation examples below.
- Every other value is assembled at runtime from prefix fragments, so that neither push
  protection nor the detect-secrets hook sees a token-shaped literal in a committed file.
- Values match their detector pattern but are not live credentials; formats with an embedded
  checksum fail it.

Nothing under src/ may import this module.
"""

import contextlib
import re
import string
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Source: AWS documentation, "Managing access keys for IAM users" (example key pair).
AWS_EXAMPLE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
# Source: AWS documentation, "Managing access keys for IAM users" (example key pair).
# pragma: allowlist nextline secret
AWS_EXAMPLE_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Personal-looking values for the domain models (E02-25). Never real people or numbers.
# Reserved test domain from RFC 2606 and RFC 6761.
EXAMPLE_EMAIL = "asha.verma@example.test"
# UK Ofcom range 07700 900000 to 900999, reserved for drama and documentation.
EXAMPLE_PHONE = "+44 7700 900123"
# North American 555-0100 to 555-0199, reserved for fictional use.
EXAMPLE_PHONE_US = "+1 202 555 0143"
EXAMPLE_PERSON = "Asha Verma"

_ALNUM = string.ascii_letters + string.digits
_UPPER_DIGITS = string.ascii_uppercase + string.digits
_URL_SAFE = _ALNUM + "_-"
_BASE64 = _ALNUM + "+/"
_PEM_MARKER = "PRIV" + "ATE KEY"


@dataclass(frozen=True)
class SecretShape:
    """The shape of one kind of secret, as a detector is expected to recognise it."""

    kind: str
    prefix: tuple[str, ...]
    alphabet: str
    length: int
    body_pattern: str
    suffix: tuple[str, ...] = ()
    example_body: str | None = None
    pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        whole = (
            re.escape("".join(self.prefix))
            + f"(?:{self.body_pattern})"
            + re.escape("".join(self.suffix))
        )
        object.__setattr__(self, "pattern", re.compile(whole))

    def example(self) -> str:
        """Return the deterministic example body."""
        if self.example_body is not None:
            return self.example_body
        repeats = self.length // len(self.alphabet) + 1
        return (self.alphabet * repeats)[: self.length]


def _cls(alphabet: str) -> str:
    return "[" + re.escape(alphabet) + "]"


def _repeat(alphabet: str, length: int) -> str:
    return (alphabet * (length // len(alphabet) + 1))[:length]


_PEM_BODY = "\n".join(_repeat(_BASE64[i:] + _BASE64[:i], 64) for i in range(4))

SECRET_SHAPES: dict[str, SecretShape] = {
    shape.kind: shape
    for shape in (
        SecretShape(
            kind="aws_access_key",
            prefix=("AK", "IA"),
            alphabet=_UPPER_DIGITS,
            length=16,
            body_pattern=_cls(_UPPER_DIGITS) + "{16}",
        ),
        SecretShape(
            kind="github_token",
            prefix=("gh", "p_"),
            alphabet=_ALNUM,
            length=36,
            body_pattern=_cls(_ALNUM) + "{36}",
            # The last six characters are GitHub's CRC32 checksum; zeros make it fail.
            example_body=_repeat(_ALNUM, 30) + "000000",
        ),
        SecretShape(
            kind="llm_api_key",
            prefix=("s", "k-"),
            alphabet=_ALNUM,
            length=40,
            body_pattern=_cls(_ALNUM) + "{40}",
        ),
        SecretShape(
            kind="google_api_key",
            prefix=("AI", "za"),
            alphabet=_URL_SAFE,
            length=35,
            body_pattern=_cls(_URL_SAFE) + "{35}",
        ),
        SecretShape(
            kind="slack_token",
            prefix=("xo", "xb-"),
            alphabet=string.digits + _ALNUM + "-",
            length=37,
            body_pattern="[0-9]{12}-" + _cls(_ALNUM) + "{24}",
            example_body=_repeat(string.digits, 12) + "-" + _repeat(_ALNUM, 24),
        ),
        SecretShape(
            kind="jwt",
            prefix=("ey", "J"),
            alphabet=_URL_SAFE + ".",
            length=47,
            body_pattern=(
                _cls(_URL_SAFE) + "{13,}" + r"\." + _cls(_URL_SAFE) + "{16,}"
                r"\." + _cls(_URL_SAFE) + "{16,}"
            ),
            example_body=_repeat(_URL_SAFE, 13) + "." + _repeat(_ALNUM, 16) + "." + "x" * 16,
        ),
        SecretShape(
            kind="private_key",
            prefix=("-----BEG", "IN ", _PEM_MARKER, "-----\n"),
            alphabet=_BASE64 + "\n",
            length=4 * 64 + 3,
            body_pattern=f"(?:{_cls(_BASE64)}{{64}}\\n){{3}}{_cls(_BASE64)}{{64}}",
            suffix=("\n-----E", "ND ", _PEM_MARKER, "-----"),
            example_body=_PEM_BODY,
        ),
        SecretShape(
            kind="bearer",
            prefix=("Bear", "er "),
            alphabet=_URL_SAFE,
            length=32,
            body_pattern=_cls(_URL_SAFE) + "{32}",
        ),
        SecretShape(
            kind="basic_auth_url",
            prefix=("https://", "user:"),
            alphabet=_ALNUM,
            length=12,
            body_pattern=_cls(_ALNUM) + "{12}",
            suffix=("@host", ".invalid/"),
        ),
        # Provider key shapes used by configuration tests (E03-15).
        SecretShape(
            kind="anthropic_api_key",
            prefix=("s", "k-", "an", "t-"),
            alphabet=_URL_SAFE,
            length=95,
            body_pattern=_cls(_URL_SAFE) + "{95}",
        ),
        SecretShape(
            kind="openai_project_key",
            prefix=("s", "k-", "pr", "oj-"),
            alphabet=_ALNUM,
            length=48,
            body_pattern=_cls(_ALNUM) + "{48}",
        ),
        SecretShape(
            kind="xai_api_key",
            prefix=("xa", "i-"),
            alphabet=_ALNUM,
            length=80,
            body_pattern=_cls(_ALNUM) + "{80}",
        ),
    )
}


def build_secret(kind: str, body: str) -> str:
    """Assemble a secret of the given kind around ``body``.

    Raises:
        KeyError: ``kind`` is not in SECRET_SHAPES.
        ValueError: the body uses characters outside the alphabet or the result does not
            match the shape's pattern (for example a wrong length).
    """
    shape = SECRET_SHAPES[kind]
    stray = sorted(set(body) - set(shape.alphabet))
    if stray:
        raise ValueError(f"{kind}: body contains characters outside the alphabet: {stray!r}")
    value = "".join(shape.prefix) + body + "".join(shape.suffix)
    if not shape.pattern.fullmatch(value):
        raise ValueError(f"{kind}: body does not produce a value that matches the pattern")
    return value


def example_secret(kind: str) -> str:
    """Return the fixed example value for ``kind``; the same on every call."""
    return build_secret(kind, SECRET_SHAPES[kind].example())


def make_tree(spec: dict[str, bytes | str]) -> Path:
    """Build a fresh directory from ``spec`` (relative POSIX path -> file content).

    A parent directory is created as needed. Returns the new, otherwise-empty root; the caller
    is responsible for cleaning it up (or lets the OS temp-directory cleanup do it).
    """
    root = Path(tempfile.mkdtemp(prefix="codekavach-tree-"))
    for rel_path, content in spec.items():
        full_path = root / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            full_path.write_text(content, encoding="utf-8")
        else:
            full_path.write_bytes(content)
    return root


def make_hostile_tree() -> Path:
    """Build, on demand, a small tree exercising every ingest discovery safety limit (E06-01).

    Not committed as static fixtures under ``tests/fixtures/``: a 12 MB file and a 200 000-line
    bundle would both be rejected by the ``check-added-large-files`` pre-commit hook
    (512 KB limit), so this factory builds them fresh in a temporary directory instead. Returns
    the tree's root; the caller is responsible for cleanup.
    """
    root = Path(tempfile.mkdtemp(prefix="codekavach-hostile-"))

    (root / "normal.py").write_text("x = 1\n", encoding="utf-8")

    # A file over any plausible max_file_size_bytes default.
    large = root / "huge.bin"
    with large.open("wb") as handle:
        handle.write(b"A" * (12 * 1024 * 1024))

    # A path far longer than the 4096-byte cap.
    try:
        long_dir = root / ("d" * 200)
        long_dir.mkdir()
        remaining = 5000 - len(str(long_dir))
        long_name = "f" * max(remaining, 1) + ".txt"
        (long_dir / long_name).write_text("x\n", encoding="utf-8")
    except OSError:
        pass  # the host file system itself refuses the name; the walk never sees it either

    # 40 levels of nested, otherwise-ordinary directories.
    try:
        deep = root
        for level in range(40):
            deep = deep / f"level{level}"
        deep.mkdir(parents=True)
        (deep / "bottom.py").write_text("y = 2\n", encoding="utf-8")
    except OSError:
        pass  # the host's own path-length limit (e.g. Windows without long-path support)

    # A symlinked directory pointing outside the root.
    outside = Path(tempfile.mkdtemp(prefix="codekavach-outside-"))
    (outside / "secret.py").write_text("z = 3\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        # symlinks need a privilege this host does not grant; the case is simply absent then
        (root / "escape").symlink_to(outside, target_is_directory=True)

    # A symlink loop (a directory symlinked to its own ancestor).
    loop_parent = root / "loopy"
    loop_parent.mkdir()
    with contextlib.suppress(OSError):
        (loop_parent / "self").symlink_to(loop_parent, target_is_directory=True)

    # Invalid UTF-8 (a lone continuation byte, valid in no supported encoding's strict mode).
    (root / "invalid.txt").write_bytes(b"\xff\xfe\x00bad")

    # A file name containing a bidi override and a zero-width space (Trojan Source vectors).
    bidi_name = "re\u202eadme\u200b.txt"
    with contextlib.suppress(OSError):
        (root / bidi_name).write_text("hidden name\n", encoding="utf-8")

    # A 200 000-line minified-looking bundle.
    minified = root / "bundle.min.js"
    with minified.open("w", encoding="utf-8") as handle:
        for i in range(200_000):
            handle.write(f"var x{i}=1;")
            handle.write("\n" if i % 1000 == 0 else "")

    # A lockfile: returned by discovery (SCA needs it), classified as nothing special.
    (root / "package-lock.json").write_text('{"lockfileVersion": 2}\n', encoding="utf-8")

    return root
