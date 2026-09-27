"""Structured logging setup and redaction.

Owning epic: E01 (ADR-0005). Normative layout: docs/ARCHITECTURE.md section 3.

Event style::

    log = get_logger(__name__)
    log.info("stage_finished", stage="parse", files=412, duration_ms=1830)

Event names are snake_case constants; data goes in key-value pairs and is never interpolated
into the event string, because redaction by key depends on it. Never log file contents,
slices, payload text, prompts, model responses, vault entries or secrets; log sizes, counts,
hashes (payload_hash) and identifiers (candidate_id) instead. Only this package may call
logging.getLogger or structlog.get_logger.
"""

from codekavach.core.log.config import (
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)

__all__ = ["bind_scan_context", "clear_scan_context", "configure_logging", "get_logger"]
