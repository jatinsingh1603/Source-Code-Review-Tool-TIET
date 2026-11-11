from django.utils.safestring import mark_safe
from django.utils.html import escape


def f(name):
# ruleid: python.xss.html-from-dynamic-string
    return mark_safe("<b>" + name + "</b>")


def g():
# ok: python.xss.html-from-dynamic-string
    return mark_safe("<b>fixed</b>")


def h(name):
# ok: python.xss.html-from-dynamic-string
    return mark_safe("<b>" + escape(name) + "</b>")
