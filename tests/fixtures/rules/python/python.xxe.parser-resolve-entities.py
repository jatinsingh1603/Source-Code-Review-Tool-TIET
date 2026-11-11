from lxml import etree


def p():
# ruleid: python.xxe.parser-resolve-entities
    return etree.XMLParser(resolve_entities=True)


def q():
# ok: python.xxe.parser-resolve-entities
    return etree.XMLParser(resolve_entities=False, no_network=True)
