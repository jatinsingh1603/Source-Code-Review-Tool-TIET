from flask import request


def read_form(field_name):
    return request.form.get(field_name), request.form.getlist(field_name)
