import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, SecretStr

from codekavach.core.log import configure_logging, get_logger
from codekavach.core.log.redaction import (
    MAX_DEPTH,
    MAX_STRING_LENGTH,
    MAX_TRACEBACK_LENGTH,
    RedactionProcessor,
    register_pattern,
    registered_patterns,
    scrub_text,
)
from tests.support.redaction import capture, json_events, restore_redaction_patterns
from tests.support.synthetic import SECRET_SHAPES, example_secret

__all__ = ["restore_redaction_patterns"]
PROCESSOR = RedactionProcessor()
HEX64 = "3f" * 32
UUID = "123e4567-e89b-12d3-a456-426614174000"


@pytest.fixture(autouse=True)
def reset_logging() -> Iterator[None]:
    yield
    configure_logging(force=True)


def run(**event: Any) -> Any:
    return PROCESSOR(None, "info", {"event": "e", **event})


def test_acceptance_examples() -> None:
    buffer = capture("json")
    password = "hunter2hunter2"  # pragma: allowlist secret
    get_logger("t").info("login", password=password, user="alice")
    get_logger("t").info("usage", token_counts={"prompt": 812, "completion": 96}, max_tokens=1024)
    source = "def fee(x): return x * 0.02"
    get_logger("t").info("sending", payload=source)
    login, usage, sending = json_events(buffer)
    assert (login["password"], login["user"]) == ("<redacted>", "alice")
    assert usage["token_counts"] == {"prompt": 812, "completion": 96}
    assert usage["max_tokens"] == 1024
    assert sending["payload"] == f"<code:len={len(source)}>"
    assert source not in buffer.getvalue()


@pytest.mark.parametrize("kind", sorted(SECRET_SHAPES))
@pytest.mark.parametrize("fmt", ["json", "console"])
def test_secrets_are_scrubbed_everywhere(kind: str, fmt: str) -> None:
    secret = example_secret(kind)
    buffer = capture(fmt)
    log = get_logger("t")
    log.info(f"event with {secret} inside", nested=["x", {"deep": [f"v {secret}"]}])  # noqa: G004
    try:
        raise ValueError(f"failure near {secret}")
    except ValueError:
        log.exception("failed")
    output = buffer.getvalue()
    for piece in re.split(r"\s+", secret):
        if len(piece) >= 12:
            assert piece not in output, kind


def test_safe_values_survive() -> None:
    event = run(digest=HEX64, uuid=UUID, where=Path("src/app.py"), note=f"hash {HEX64} ok")
    assert (event["digest"], event["uuid"], event["where"]) == (HEX64, UUID, Path("src/app.py"))
    assert event["note"] == f"hash {HEX64} ok"


def test_stdlib_records_are_scrubbed() -> None:
    buffer = capture("json")
    logging.getLogger("httpx").warning("Authorization: Bearer %s", "A" * 40)
    assert "A" * 40 not in buffer.getvalue()
    assert "<redacted:bearer>" in buffer.getvalue()


def test_lines_rule_and_traceback_exemption() -> None:
    buffer = capture("json")
    note = "\n".join(f"line {index}" for index in range(12))
    log = get_logger("t")
    log.info("n", note=note)
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        log.exception("failed")
    first, second = json_events(buffer)
    assert first["note"] == "<text:lines=12>"
    frames = second["exception"][0]["frames"]
    assert frames[0]["filename"].endswith("test_redaction.py")
    assert isinstance(frames[0]["lineno"], int)


def test_traceback_is_cut() -> None:
    event = PROCESSOR(None, "error", {"event": "e", "exception": "x" * (MAX_TRACEBACK_LENGTH + 5)})
    assert event["exception"].endswith("<truncated>")
    assert len(event["exception"]) == MAX_TRACEBACK_LENGTH + len("<truncated>")


def test_long_strings_and_bytes_and_secret_types() -> None:
    event = run(
        long="y" * (MAX_STRING_LENGTH + 1),
        raw=b"abc",
        hidden=SecretStr("hunter2hunter2"),
        other=object(),
        error=ValueError(f"key {example_secret('aws_access_key')}"),
    )
    assert event["long"] == f"<str:len={MAX_STRING_LENGTH + 1}>"
    assert event["raw"] == "<bytes:len=3>"
    assert event["hidden"] == "<redacted>"
    assert event["other"].startswith("<object object")
    assert event["error"] == "key <redacted:aws_access_key>"


class Loose(BaseModel):
    count: int


def test_validation_input_pattern() -> None:
    marker = "SECRETINPUTVALUE"
    buffer = capture("json")
    try:
        Loose.model_validate({"count": marker})
    except Exception:  # noqa: BLE001 - logged below
        get_logger("t").exception("validation failed")
    assert marker not in buffer.getvalue()


def test_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: RedactionProcessor, event_dict: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("bug")

    monkeypatch.setattr(RedactionProcessor, "_redact", broken)
    buffer = capture("json")
    get_logger("t").warning("original", secret_value="visible")  # pragma: allowlist secret
    (event,) = json_events(buffer)
    assert event == {
        "event": "log_event_suppressed",
        "reason": "redaction_error",
        "level": "warning",
    }


def near_misses() -> dict[str, str]:
    return {
        "aws_access_key": example_secret("aws_access_key")[:-1],
        "github_token": example_secret("github_token")[:30],
        "llm_api_key": "sk-" + "a" * 19,  # pragma: allowlist secret
        "google_api_key": example_secret("google_api_key")[:-1],
        "slack_token": "xoxb-short",
        "jwt": "eyJshort.abc.def",
        "private_key": example_secret("private_key").replace("PRIVATE", "PUBLIC"),
        "bearer": "Bearer abc",
        "basic_auth_url": "https://host.invalid/",
    }


@pytest.mark.parametrize("kind", sorted(SECRET_SHAPES))
def test_near_miss_negatives(kind: str) -> None:
    near = near_misses()[kind]
    assert scrub_text(near) == near, kind


def test_assignment_keeps_the_key() -> None:
    assert scrub_text("password=hunter2hunter2 next") == "password=<redacted:assignment> next"
    assert scrub_text("API-KEY: 'abcd1234'").startswith("API-KEY: '<redacted:assignment>")


@pytest.mark.parametrize("key", ["API-Key", "apiKey", "X_API_KEY", "password_hash", "Cookie"])
def test_sensitive_key_normalisation(key: str) -> None:
    assert run(**{key: "value"})[key] == "<redacted>"


@pytest.mark.parametrize("key", ["token_counts", "token_estimate", "max_tokens", "prompt_tokens",
                                 "token_id", "payload_hash", "entry_hash"])  # fmt: skip
def test_safe_keys(key: str) -> None:
    assert run(**{key: "value"})[key] == "value"


def test_non_string_values_under_sensitive_keys() -> None:
    event = run(password=12, token=None, secret=True, salt=[1, 2])
    assert (event["password"], event["token"], event["secret"]) == (12, None, True)
    assert event["salt"] == [1, 2]


def test_code_keys_for_containers() -> None:
    event = run(code=["a", "b"], mapping={"x": 1}, body=b"xyz")
    assert event["code"] == "<code:items=2>"
    assert event["mapping"] == "<code:items=1>"
    assert event["body"] == "<code:len=3>"


def test_depth_sets_tuples_keys_and_cycles() -> None:
    deep: Any = "bottom"
    for _ in range(MAX_DEPTH + 3):
        deep = [deep]
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    event = run(deep=deep, items={3}, pair=(1, "x"), keys={1: "one"}, loop=cyclic)
    flat = str(event["deep"])
    assert "<nested>" in flat
    assert "bottom" not in flat
    assert event["items"] == [3]
    assert event["pair"] == (1, "x")
    assert event["keys"] == {"1": "one"}
    assert "<nested>" in str(event["loop"])


def test_caller_dict_is_not_mutated() -> None:
    value = "hunter2hunter2"  # pragma: allowlist secret
    nested = {"password": value, "list": ["a"]}
    event = {"event": "e", "nested": nested}
    PROCESSOR(None, "info", event)
    assert nested == {"password": value, "list": ["a"]}


def test_register_pattern(restore_redaction_patterns: None) -> None:
    register_pattern("ck_internal", re.compile(r"CKINT-[0-9]{6}"))
    assert "ck_internal" in registered_patterns()
    assert scrub_text("id CKINT-123456") == "id <redacted:ck_internal>"
    with pytest.raises(ValueError, match="already registered"):
        register_pattern("ck_internal", re.compile("x"))
    with pytest.raises(ValueError, match="snake_case"):
        register_pattern("Bad-Name", re.compile("x"))
