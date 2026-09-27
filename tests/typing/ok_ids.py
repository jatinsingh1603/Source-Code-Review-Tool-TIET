"""Every id constructor returns its own NewType."""

from codekavach.core.models.ids import (
    CandidateId,
    FindingId,
    PayloadId,
    ProjectId,
    ScanId,
    SliceId,
    new_candidate_id,
    new_finding_id,
    new_payload_id,
    new_project_id,
    new_scan_id,
    new_slice_id,
)

project: ProjectId = new_project_id()
scan: ScanId = new_scan_id()
candidate: CandidateId = new_candidate_id()
code_slice: SliceId = new_slice_id()
payload: PayloadId = new_payload_id()
finding: FindingId = new_finding_id()
plain: str = finding
