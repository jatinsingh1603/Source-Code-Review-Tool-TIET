def outer(value):
    def inner(value):
        value = value + 1
        return value

    return inner(value)


double_it = lambda value: value * 2
