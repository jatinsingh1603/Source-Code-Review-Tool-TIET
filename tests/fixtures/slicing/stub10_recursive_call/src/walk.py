def walk(node, depth):
    if node is None:
        return depth
    return walk(node.next, depth + 1)
