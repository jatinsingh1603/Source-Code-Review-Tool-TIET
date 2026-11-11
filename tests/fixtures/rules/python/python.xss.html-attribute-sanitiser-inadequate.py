import html
import bleach


def link(next_url):
# ruleid: python.xss.html-attribute-sanitiser-inadequate
    return "<a href='" + bleach.clean(next_url) + "'>go</a>"


def link_safe(next_url):
# ok: python.xss.html-attribute-sanitiser-inadequate
    return "<a href='" + html.escape(next_url) + "'>go</a>"
