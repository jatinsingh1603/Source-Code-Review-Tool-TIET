"""Serialisation helper for statements and cached customer profiles."""

import json
import pickle


def dump_statement(rows):
    """A statement as JSON text."""
    return json.dumps([list(map(str, row)) for row in rows])


def load_cached_profile(blob):
    """A customer profile read back from the shared cache."""
    return pickle.loads(blob)


def load_profile(text):
    """A customer profile from its JSON form."""
    return json.loads(text)
