from flask import render_template_string


def page(name):
    html = "<p>" + name + "</p>"
    return render_template_string(html)
