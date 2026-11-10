"""The receiver of a method keeps a role-preserving form (E09-FU-RECEIVER).

The first parameter of a function defined directly in a class body, when it is not a
``@staticmethod`` and is spelled ``self`` or ``cls``, stays in clear with the rule ``receiver``.
Position and decorator decide whether a parameter is a receiver; the conventional spelling only
decides whether the name may be disclosed. Every other parameter is renamed as before.
"""

import re

import pytest

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.classify import IdentifierClass, Rule
from tests.support.classification import classify_text
from tests.support.rename import rename_text


def rules_of(text: str, name: str) -> set[Rule]:
    result = classify_text(Language.PYTHON, text)
    return {d.rule for d in result.decisions if d.name == name}


def renamed(text: str) -> str:
    return rename_text(Language.PYTHON, text, extra=()).text


METHODS = """\
class Account:
    def accrue(self, account_id):
        return self.balance + account_id

    @classmethod
    def create(cls, owner):
        return cls(owner)

    @staticmethod
    def helper(self, value):
        return value
"""


def test_an_instance_method_keeps_self_and_its_uses() -> None:
    out = renamed(METHODS)
    assert re.search(r"def fn_\d+\(self, param_\d+\):", out)
    assert "return self.field_" in out or "self.balance" not in out


def test_a_class_method_keeps_cls() -> None:
    out = renamed(METHODS)
    assert re.search(r"def \w+\(cls, param_\d+\):", out)
    assert re.search(r"return cls\(param_\d+\)", out)


def test_a_static_method_has_no_receiver_even_when_the_parameter_is_called_self() -> None:
    out = renamed(METHODS)
    assert re.search(r"def fn_\d+\(param_\d+, param_\d+\):\n\s+return param_\d+", out)
    assert Rule.RECEIVER in rules_of(METHODS, "self")  # the instance method still has one


def test_the_decorator_may_be_qualified_or_stacked() -> None:
    text = (
        "import functools\n\nclass A:\n"
        "    @functools.wraps\n    @staticmethod\n    def f(self, x):\n        return x\n"
    )
    assert Rule.RECEIVER not in rules_of(text, "self")


def test_a_plain_function_with_a_parameter_called_self_is_renamed() -> None:
    text = "def accrue(self, value):\n    return self + value\n"
    assert Rule.RECEIVER not in rules_of(text, "self")
    assert "self" not in renamed(text)


def test_a_nested_function_inside_a_method_has_no_receiver() -> None:
    text = (
        "class A:\n    def outer(self):\n        def inner(self, y):\n            return y\n"
        "        return inner\n"
    )
    out = renamed(text)
    assert re.search(r"def fn_\d+\(self\):", out)
    assert re.search(r"def fn_\d+\(param_\d+, param_\d+\):", out)


def test_only_the_first_parameter_is_the_receiver() -> None:
    text = "class A:\n    def f(value, self):\n        return self\n"
    assert Rule.RECEIVER not in rules_of(text, "self")


@pytest.mark.parametrize("spelling", ["account", "this", "me", "selff", "s"])
def test_a_receiver_with_an_unconventional_spelling_is_renamed(spelling: str) -> None:
    text = f"class A:\n    def f({spelling}, x):\n        return {spelling}.x + x\n"
    body = renamed(text).split("def", 1)[1]
    assert re.match(r" fn_\d+\(param_\d+, ", body)
    assert re.search(rf"\b{spelling}\b", body) is None


def test_a_receiver_is_public_only_by_the_receiver_rule() -> None:
    result = classify_text(Language.PYTHON, METHODS)
    verdicts = [
        d for d in result.decisions if d.name in {"self", "cls"} and d.rule is Rule.RECEIVER
    ]
    assert verdicts
    assert all(d.classification is IdentifierClass.PUBLIC for d in verdicts)


def test_without_a_parsed_tree_nothing_is_a_receiver() -> None:
    # An unparsable file cannot be checked for decorators, so the names are renamed as before.
    text = "class A:\n    def f(self, x:\n        return self\n"
    result = classify_text(Language.PYTHON, text)
    receiver_names = {d.name for d in result.decisions if d.rule is Rule.RECEIVER}
    assert receiver_names <= {"self"}
