"""``decode``: UTF-8, UTF-16 with a BOM, cp1252 fallback, and the undecodable case (E06-01)."""

import pytest

from codekavach.ingest.encoding import UndecodableFileError, decode


def test_utf8_plain() -> None:
    text, encoding = decode("héllo".encode())
    assert (text, encoding) == ("héllo", "utf-8")


def test_utf8_with_bom() -> None:
    data = b"\xef\xbb\xbf" + "héllo".encode()
    text, encoding = decode(data)
    assert (text, encoding) == ("héllo", "utf-8-sig")


def test_utf16_le_with_bom() -> None:
    data = "héllo".encode("utf-16-le")
    bom = b"\xff\xfe"
    text, encoding = decode(bom + data)
    assert (text, encoding) == ("héllo", "utf-16-le")


def test_utf16_be_with_bom() -> None:
    data = "héllo".encode("utf-16-be")
    bom = b"\xfe\xff"
    text, encoding = decode(bom + data)
    assert (text, encoding) == ("héllo", "utf-16-be")


def test_cp1252_fallback() -> None:
    # 0x92 is a right single quotation mark in cp1252; invalid as UTF-8 continuation on its own.
    data = b"it\x92s"
    text, encoding = decode(data)
    assert encoding == "cp1252"
    assert text == "it" + chr(0x2019) + "s"


def test_undecodable_raises() -> None:
    # Invalid UTF-8 (a lone continuation byte) and invalid ascii (any byte over 0x7f); cp1252
    # maps every byte, so a non-default legacy_encoding is needed to force this case.
    with pytest.raises(UndecodableFileError):
        decode(b"\x80\x81\x82", legacy_encoding="ascii")


def test_undecodable_bom_prefixed_data_still_raises_cleanly() -> None:
    # Starts with the UTF-16 LE BOM but the remaining bytes are an odd length, which is not a
    # valid UTF-16 sequence; must raise UndecodableFileError, not an uncaught UnicodeDecodeError.
    with pytest.raises(UndecodableFileError):
        decode(b"\xff\xfe" + b"\x00")


def test_undecodable_names_what_was_tried() -> None:
    with pytest.raises(UndecodableFileError) as excinfo:
        decode(b"\x80\x81", legacy_encoding="ascii")
    assert "utf-8" in str(excinfo.value)
    assert "ascii" in str(excinfo.value)
