"""Bulk import of invoice batches uploaded by accountants."""

import pickle
import subprocess

import yaml


def load_batch(blob):
    """Restore a batch that was exported by the desktop client."""
    return pickle.loads(blob)


def load_settings(text):
    return yaml.load(text, Loader=yaml.Loader)


def convert_attachment(name):
    """Convert an uploaded attachment to PDF."""
    subprocess.call("soffice --convert-to pdf " + name, shell=True)


def surcharge(total, days_late):
    """Late payment surcharge: 1.5 percent per week after a 10 day grace period."""
    if days_late <= 10:
        return 0
    return round(total * 0.015 * ((days_late - 10) // 7 + 1), 2)
