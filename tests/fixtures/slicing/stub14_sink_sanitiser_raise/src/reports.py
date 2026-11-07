from tools.runner import run_report


def build(name):
    safe = run_report(name)
    return safe
