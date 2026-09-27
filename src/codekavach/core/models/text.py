r"""Text wrappers that keep raw client code and sanitised text apart, plus the line model.

Owning epic: E02.

``RawCode`` holds client code, paths, identifiers or any other unsanitised text. ``SanitisedText``
holds text produced by the privacy layer, the only kind that may reach ``codekavach.llm``
(invariant I2). The two classes are final and unrelated: neither is a ``str`` and neither
converts into the other, so mixing them is a ``mypy --strict`` error and a Pydantic validation
error. ``repr``, ``str`` and ``format`` print a redacted form; the content is reachable only
through ``expose()``, which is easy to find in review.

Who may construct them:

- ``RawCode(...)``: anyone; labelling a string as raw is always safe.
- ``SanitisedText(...)``: only code in ``codekavach.privacy.*`` (enforced by E02-28).

Pydantic: a ``RawCode`` field accepts a ``RawCode`` or a ``str`` in Python mode. A
``SanitisedText`` field accepts only a ``SanitisedText`` instance in Python mode, but any string
in JSON mode (``model_validate_json``), which is needed to reload stored payloads and ledger
files. That is a deliberate, greppable loophole for storage; the egress guard (E12) re-scans
every payload before it is sent. Both serialise to a plain JSON string; Python-mode
``model_dump()`` keeps the wrapper instances.

Validation errors: ``KavachModel`` hides input values in ``str(ValidationError)``, but
``ValidationError.errors()`` still includes them; code that logs error details must call
``errors(include_input=False)``.

Line model (normative for the whole project): a line ends at ``\n``; a ``\r`` directly before
that ``\n`` belongs to the terminator; a last line without a terminator is a line; the empty
string has zero lines; every other character, including a lone ``\r``, form feed, ``\x0b``,
``\x1c`` to ``\x1e``, ``\x85``, U+2028 and U+2029, is ordinary text. ``split_lines`` is the only
implementation; never use the str method that splits on every Unicode line boundary.
"""

from typing import Any, NoReturn, final

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines according to the project's line model."""
    if text == "":
        return []
    parts = text.split("\n")
    if parts[-1] == "":
        parts.pop()
    return [part[:-1] if part.endswith("\r") else part for part in parts]


def _redacted(kind: str, value: str) -> str:
    lines = len(split_lines(value))
    return f"{kind}(<redacted, {len(value)} chars, {lines} line{'' if lines == 1 else 's'}>)"


def _check_str(kind: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{kind} wraps a str, not {type(value).__name__}")
    return value


def _immutable(kind: str) -> NoReturn:
    raise AttributeError(f"{kind} is immutable")


def _serialise(value: "RawCode | SanitisedText") -> str:
    return value.expose()


@final
class RawCode:
    """Unsanitised client text. Never send it to codekavach.llm (invariant I2)."""

    __slots__ = ("_value",)
    _value: str

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", _check_str("RawCode", value))

    def expose(self) -> str:
        """Return the wrapped text. Call only in trusted privacy or report code."""
        return self._value

    @property
    def line_count(self) -> int:
        """Number of lines according to ``split_lines``."""
        return len(split_lines(self._value))

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if type(other) is not RawCode:
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(("RawCode", self._value))

    def __repr__(self) -> str:
        return _redacted("RawCode", self._value)

    def __str__(self) -> str:
        return _redacted("RawCode", self._value)

    def __format__(self, format_spec: str) -> str:
        return _redacted("RawCode", self._value)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        _immutable("RawCode")

    def __delattr__(self, name: str) -> NoReturn:
        _immutable("RawCode")

    def __reduce__(self) -> tuple[type["RawCode"], tuple[str]]:
        return (RawCode, (self._value,))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        from_str = core_schema.no_info_after_validator_function(cls, core_schema.str_schema())
        return core_schema.json_or_python_schema(
            json_schema=from_str,
            python_schema=core_schema.union_schema([core_schema.is_instance_schema(cls), from_str]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                _serialise, return_schema=core_schema.str_schema(), when_used="json"
            ),
        )


@final
class SanitisedText:
    """Text produced by the privacy layer; the only text codekavach.llm may receive."""

    __slots__ = ("_value",)
    _value: str

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", _check_str("SanitisedText", value))

    def expose(self) -> str:
        """Return the wrapped text."""
        return self._value

    @property
    def line_count(self) -> int:
        """Number of lines according to ``split_lines``."""
        return len(split_lines(self._value))

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if type(other) is not SanitisedText:
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(("SanitisedText", self._value))

    def __repr__(self) -> str:
        return _redacted("SanitisedText", self._value)

    def __str__(self) -> str:
        return _redacted("SanitisedText", self._value)

    def __format__(self, format_spec: str) -> str:
        return _redacted("SanitisedText", self._value)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        _immutable("SanitisedText")

    def __delattr__(self, name: str) -> NoReturn:
        _immutable("SanitisedText")

    def __reduce__(self) -> tuple[type["SanitisedText"], tuple[str]]:
        return (SanitisedText, (self._value,))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        from_str = core_schema.no_info_after_validator_function(cls, core_schema.str_schema())
        return core_schema.json_or_python_schema(
            json_schema=from_str,
            python_schema=core_schema.is_instance_schema(cls),
            serialization=core_schema.plain_serializer_function_ser_schema(
                _serialise, return_schema=core_schema.str_schema(), when_used="json"
            ),
        )
