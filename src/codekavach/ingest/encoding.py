"""Text decoding without statistical charset guessing (E06-01).

Owning epic: E06.

Tried in order: a UTF-8 or UTF-16 byte-order mark, then strict UTF-8, then one configured legacy
fallback (``ingest.legacy_encoding``, default ``cp1252``) with ``errors="strict"``. No statistical
guessing: a wrong guess silently corrupts identifiers, which then get pseudonymised
inconsistently, and the corruption is invisible until a client compares the report against their
own file.
"""

import codecs

UTF8_BOM = codecs.BOM_UTF8
UTF16_LE_BOM = codecs.BOM_UTF16_LE
UTF16_BE_BOM = codecs.BOM_UTF16_BE


class UndecodableFileError(Exception):
    """No encoding in the tried order could decode the file; never guessed, never silently lossy."""

    def __init__(self, tried: tuple[str, ...]) -> None:
        self.tried = tried
        super().__init__(f"could not decode: tried {', '.join(tried)}")


def decode(data: bytes, legacy_encoding: str = "cp1252") -> tuple[str, str]:
    """Decode ``data``, returning ``(text, encoding_name)``.

    Raises:
        UndecodableFileError: UTF-8, UTF-16 (with a BOM) and ``legacy_encoding`` all failed.
    """
    if data.startswith(UTF8_BOM):
        try:
            return data[len(UTF8_BOM) :].decode("utf-8"), "utf-8-sig"
        except UnicodeDecodeError:
            raise UndecodableFileError(("utf-8-sig",)) from None
    if data.startswith(UTF16_LE_BOM):
        try:
            return data[len(UTF16_LE_BOM) :].decode("utf-16-le"), "utf-16-le"
        except UnicodeDecodeError:
            raise UndecodableFileError(("utf-16-le",)) from None
    if data.startswith(UTF16_BE_BOM):
        try:
            return data[len(UTF16_BE_BOM) :].decode("utf-16-be"), "utf-16-be"
        except UnicodeDecodeError:
            raise UndecodableFileError(("utf-16-be",)) from None
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode(legacy_encoding), legacy_encoding
    except (UnicodeDecodeError, LookupError):
        pass
    raise UndecodableFileError(("utf-8", "utf-16 (bom)", legacy_encoding))
