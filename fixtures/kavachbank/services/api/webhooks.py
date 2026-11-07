"""Outbound calls to partner banks."""

from urllib.parse import urlparse

import requests

import config


def fetch_partner_rate(url):
    """The partner's published rate; only hosts we have agreed with may be called."""
    host = urlparse(url).hostname
    if host not in config.ALLOWED_PARTNER_HOSTS:
        raise ValueError("partner host is not allowed")
    return requests.get(url, timeout=5).json()
