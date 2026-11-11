from flask import render_template_string, request


def page():
# ruleid: python.ssti.template-from-input
    return render_template_string("<h1>" + request.args["t"] + "</h1>")


def page_safe(name):
# ok: python.ssti.template-from-input
    return render_template_string("<h1>{{ name }}</h1>", name=name)
