"""Secret candidates are masked: type, preview, entropy and place, never the value (issue 236)."""

from codekavach.analysis.secrets.mask import mask_secret_values
from codekavach.analysis.secrets.stage import candidates_for, hits_in, secret_registry
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID, AWS_EXAMPLE_SECRET_ACCESS_KEY

TEXT = (
    "import os\n"
    f'AWS_ACCESS_KEY_ID = "{AWS_EXAMPLE_ACCESS_KEY_ID}"\n'
    f'AWS_SECRET_ACCESS_KEY = "{AWS_EXAMPLE_SECRET_ACCESS_KEY}"\n'
)


def _candidates(text: str = TEXT) -> list[Candidate]:
    hits = hits_in(text, "cfg.py", Language.PYTHON, Settings(), secret_registry())
    return candidates_for("cfg.py", Language.PYTHON, hits)


def test_hits_become_cwe_798_candidates_with_lines() -> None:
    found = _candidates()
    assert {c.locations[0].start_line for c in found} == {2, 3}
    assert all(798 in c.cwe for c in found)
    assert "secret.aws_access_key" in {c.rule_id for c in found}


def test_no_value_in_any_candidate_field() -> None:
    for candidate in _candidates():
        dump = candidate.model_dump_json()
        assert AWS_EXAMPLE_ACCESS_KEY_ID not in dump
        assert AWS_EXAMPLE_SECRET_ACCESS_KEY not in dump
        assert dict(candidate.properties)["secret.preview"].count("*") >= 4


def test_fingerprint_survives_rotation() -> None:
    rotated = TEXT.replace(AWS_EXAMPLE_ACCESS_KEY_ID, "AKIAZZZZZZZZZZZZZZZZ")
    old = {c.fingerprint for c in _candidates()}
    new = {c.fingerprint for c in _candidates(rotated)}
    assert old & new


def test_masking_keeps_line_count_and_hides_values() -> None:
    masked = mask_secret_values(TEXT, "cfg.py", Language.PYTHON, Settings())
    assert masked.count("\n") == TEXT.count("\n")
    assert AWS_EXAMPLE_ACCESS_KEY_ID not in masked
    assert "<SECRET:" in masked


def test_a_secret_reference_is_not_a_hard_coded_credential() -> None:
    # The starter codekavach.toml names keys by reference; a scan of it must stay clean.
    text = (
        'api_key = "env:ANTHROPIC_API_KEY"\n'
        'token = "env:CK_SYNC_TOKEN"\n'
        'passphrase = "keyring:codekavach/vault"\n'
    )
    hits = hits_in(text, "codekavach.toml", Language.TOML, Settings(), secret_registry())
    assert hits == []
