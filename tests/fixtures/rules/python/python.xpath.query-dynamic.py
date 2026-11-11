def f(tree, name):
# ruleid: python.xpath.query-dynamic
    return tree.xpath("//user[@name='" + name + "']")


def g(tree, name):
# ok: python.xpath.query-dynamic
    return tree.xpath("//user[@name=$n]", n=name)
