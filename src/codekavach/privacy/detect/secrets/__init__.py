"""Secret detectors (E08-02): provider patterns, credential assignments and entropy.

Owning epic: E08.

Nothing in this package opens a socket or contacts a provider to check whether a credential is
live; validation is structural only. Detection runs on a slice, so a secret defined outside the
slice and only referenced inside it is not redacted here: the reference name is pseudonymised by
E09 instead.
"""
