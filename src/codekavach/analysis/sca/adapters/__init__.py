"""Optional third-party SCA matchers, run as external processes and never imported (E19-02)."""

from codekavach.analysis.sca.adapters.base import MatcherUnavailable, run_matcher
from codekavach.analysis.sca.adapters.osv_scanner import scan as osv_scan
from codekavach.analysis.sca.adapters.trivy_fs import scan as trivy_scan

ADAPTERS = {"osv-scanner": osv_scan, "trivy": trivy_scan}

__all__ = ["ADAPTERS", "MatcherUnavailable", "osv_scan", "run_matcher", "trivy_scan"]
