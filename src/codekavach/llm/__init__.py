"""LLM layer: providers, review tasks, prompts, output schemas, defences, budget, cache and consensus.

Owning epic: E22 to E24. Normative layout: docs/ARCHITECTURE.md section 3.

Invariant I2: this package accepts SanitisedPayload only and must never import raw-code packages (see .importlinter).
"""
