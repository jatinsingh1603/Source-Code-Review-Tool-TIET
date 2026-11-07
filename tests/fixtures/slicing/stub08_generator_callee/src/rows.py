def rows(path, limit):
    for line in open(path):
        yield line.strip()
