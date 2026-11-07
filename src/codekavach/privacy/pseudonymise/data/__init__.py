"""Versioned public-name allowlists, one TOML file per language (E09-02).

Owning epic: E09.

Each file opens with a comment header that records its source, its generation date and its
version, and repeats the version as a key that ``codekavach.privacy.pseudonymise.allowlist``
reads. The files are loaded through ``importlib.resources`` so that they travel in the wheel with
the package, and no file is ever read from the scanned repository.
"""
