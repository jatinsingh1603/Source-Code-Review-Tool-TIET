"""Egress guard: pre-flight leak checks on every payload before it may be sent.

Owning epic: E12. Normative layout: docs/ARCHITECTURE.md section 3.

Invariant I4: any failed check blocks the request (fail closed).
"""
