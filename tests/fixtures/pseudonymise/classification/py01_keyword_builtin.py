def convert(value):
    if value is None:
        return str(len(value))
    return sorted(value, key=len)
