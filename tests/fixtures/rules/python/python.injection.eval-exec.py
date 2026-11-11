import ast


def calc(expr):
# ruleid: python.injection.eval-exec
    return eval(expr)


def literal(expr):
# ok: python.injection.eval-exec
    return ast.literal_eval(expr)


def fixed():
# ok: python.injection.eval-exec
    return eval("1 + 1")
