import yaml


def a(text):
# ruleid: python.deser.yaml-unsafe-load
    return yaml.load(text)


def b(text):
# ruleid: python.deser.yaml-unsafe-load
    return yaml.load(text, Loader=yaml.Loader)


def c(text):
# ok: python.deser.yaml-unsafe-load
    return yaml.safe_load(text)


def d(text):
# ok: python.deser.yaml-unsafe-load
    return yaml.load(text, Loader=yaml.SafeLoader)
