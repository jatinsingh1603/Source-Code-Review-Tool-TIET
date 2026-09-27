import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification, TaintRole
from codekavach.core.models.location import Location
from codekavach.core.models.taint import TaintPath, TaintStep


def loc(path: str = "app/views.py", line: int = 1, symbol: str | None = None) -> Location:
    return Location(path=path, start_line=line, end_line=line, symbol=symbol)


def step(role: TaintRole, **kwargs: object) -> TaintStep:
    return TaintStep(location=loc(**kwargs), role=role)  # type: ignore[arg-type]


S, P, Z, K = TaintRole.SOURCE, TaintRole.PROPAGATOR, TaintRole.SANITISER, TaintRole.SINK


def test_minimal_path_validates() -> None:
    path = TaintPath(steps=(step(S), step(K, line=2)))
    assert len(path) == 2
    assert path.source.role is S
    assert path.sink.role is K


@pytest.mark.parametrize(
    ("roles", "message"),
    [
        ((S,), "at least 2"),
        ((P, K), "start with a source"),
        ((S, Z), "end with a sink"),
        ((S, S, K), "only the first step"),
        ((S, K, K), "only the last step"),
    ],
)
def test_structure_rejected(roles: tuple[TaintRole, ...], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        TaintPath(steps=tuple(step(role, line=i + 1) for i, role in enumerate(roles)))


def test_helpers_on_three_file_path() -> None:
    path = TaintPath(
        steps=(
            step(S, path="app/views.py", line=12, symbol="transfer"),
            step(P, path="app/service.py", line=5, symbol="Service.move"),
            step(Z, path="app/service.py", line=9, symbol="Service.move"),
            step(K, path="app/db.py", line=40, symbol="AccountRepo.credit"),
        )
    )
    assert path.is_sanitised
    assert path.files == ("app/views.py", "app/service.py", "app/db.py")
    assert path.is_interprocedural
    assert path.is_cross_file
    assert len(path) == 4


def test_helpers_on_single_file_looped_path() -> None:
    path = TaintPath(
        steps=(
            step(S, line=1, symbol="f"),
            step(P, line=3, symbol="f"),
            step(P, line=3, symbol="f"),
            step(K, line=5, symbol="f"),
        )
    )
    assert not path.is_sanitised
    assert path.files == ("app/views.py",)
    assert not path.is_interprocedural
    assert not path.is_cross_file
    assert len(path) == 4


def test_from_locations() -> None:
    path = TaintPath.from_locations(loc(line=1), loc(line=9), via=[loc(line=4), loc(line=6)])
    assert [s.role for s in path.steps] == [S, P, P, K]


def test_json_round_trip_and_hashable() -> None:
    path = TaintPath.from_locations(loc(line=1), loc("app/db.py", 40, "AccountRepo.credit"))
    assert TaintPath.model_validate_json(path.model_dump_json()) == path
    assert {path: 1}[path] == 1


def test_note_length() -> None:
    TaintStep(location=loc(), role=S, note="x" * 500)
    with pytest.raises(ValidationError):
        TaintStep(location=loc(), role=S, note="x" * 501)


def test_classification() -> None:
    assert TaintStep.DATA_CLASSIFICATION is DataClassification.RAW
    assert TaintPath.DATA_CLASSIFICATION is DataClassification.RAW


@given(st.lists(st.sampled_from([P, Z]), max_size=20))
def test_any_well_formed_path_validates_and_round_trips(middle: list[TaintRole]) -> None:
    roles = [S, *middle, K]
    path = TaintPath(steps=tuple(step(role, line=i + 1) for i, role in enumerate(roles)))
    assert TaintPath.model_validate_json(path.model_dump_json()) == path
