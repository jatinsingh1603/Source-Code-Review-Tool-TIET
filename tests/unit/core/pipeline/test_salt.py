import copy
import hashlib
import io
import pickle

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.log import get_logger
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.base import ArtefactForbiddenError
from codekavach.core.store.memory import InMemoryArtefactStore

VECTOR = "00112233445566778899aabbccddeeff" * 2


def test_fingerprint_vector() -> None:
    salt = ScanSalt.from_hex(VECTOR)
    expected = hashlib.sha256(b"ck-salt-fp-v1" + bytes.fromhex(VECTOR)).hexdigest()[:16]
    assert salt.fingerprint() == expected
    assert len(expected) == 16
    assert salt.reveal() == bytes.fromhex(VECTOR)


def test_redaction(log_output: io.StringIO) -> None:
    salt = ScanSalt.from_hex(VECTOR)
    raw = bytes.fromhex(VECTOR)
    texts = [repr(salt), str(salt), f"{salt}", f"{salt!r}", f"{salt:>40}"]
    get_logger("t").warning("salt_probe", salt=salt)
    texts.append(log_output.getvalue())
    for text in texts:
        assert VECTOR not in text
        assert VECTOR.upper() not in text
        assert str(raw) not in text
    assert "ScanSalt(<redacted>)" in texts[0]
    assert not hasattr(salt, "__dict__")
    with pytest.raises(TypeError):
        vars(salt)
    with pytest.raises(AttributeError):
        salt._value = b"x" * 32


def test_no_pickling_or_copying() -> None:
    salt = ScanSalt.generate()
    for call in (lambda: pickle.dumps(salt), lambda: copy.deepcopy(salt), lambda: copy.copy(salt)):
        with pytest.raises(TypeError):
            call()


def test_rejected_by_artefact_stores() -> None:
    with pytest.raises(ArtefactForbiddenError):
        InMemoryArtefactStore().put("scan.target", ScanSalt.generate(), persist=False)


def test_equality_and_hash() -> None:
    first = ScanSalt.from_hex(VECTOR)
    second = ScanSalt(bytes.fromhex(VECTOR))
    assert first == second
    assert hash(first) == hash(second)
    assert first != ScanSalt.generate()
    assert first != VECTOR


@pytest.mark.parametrize("value", [b"short", "not bytes", b""])
def test_constructor_validation(value: object) -> None:
    with pytest.raises(ValueError, match="at least 16 bytes"):
        ScanSalt(value)


@pytest.mark.parametrize("text", ["ab" * 31, "zz" * 32, "ab" * 33, 12])
def test_from_hex_validation_does_not_echo(text: object) -> None:
    with pytest.raises(ValueError) as error:
        ScanSalt.from_hex(text)
    assert str(text) not in str(error.value)


def test_generate_is_random() -> None:
    assert len(ScanSalt.generate().reveal()) == 32
    assert ScanSalt.generate() != ScanSalt.generate()


@settings(max_examples=200)
@given(st.binary(min_size=32, max_size=32))
def test_property_hex_never_leaks(raw: bytes) -> None:
    salt = ScanSalt(raw)
    for text in (repr(salt), str(salt), salt.fingerprint()):
        assert raw.hex() not in text


def test_fingerprints_differ() -> None:
    fingerprints = {ScanSalt.generate().fingerprint() for _ in range(1000)}
    assert len(fingerprints) == 1000
