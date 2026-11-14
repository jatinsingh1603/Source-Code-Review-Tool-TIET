"""The report names the scan by the id the dashboard shows, next to the pipeline id."""

from codekavach.server.reports import scan_label


def test_scan_label_matches_the_dashboard() -> None:
    assert scan_label("scn_6b14be4a8eb4c19a34d8") == "SCN-6B14BE"


def test_scan_label_is_none_for_a_pipeline_id() -> None:
    assert scan_label("scan_01M7CPMVW8C90SSZVTNS52QSJC") is None
