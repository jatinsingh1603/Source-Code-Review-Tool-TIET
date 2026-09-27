"""Egress: the guard (pre-flight leak checks), the ledger (hash chain) and the transport (the only way out).

Owning epic: E12. Normative layout: docs/ARCHITECTURE.md section 3.

Invariants I1 and I4: only privacy.egress.transport opens connections to LLM endpoints, and any failure in a privacy step aborts the request for that candidate (fail closed).
"""
