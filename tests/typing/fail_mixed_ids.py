"""A candidate id must not be accepted where a finding id is expected."""

from codekavach.core.models.ids import FindingId, new_candidate_id


def close_finding(finding_id: FindingId) -> None:
    """Pretend to close a finding."""


close_finding(new_candidate_id())  # E: arg-type
