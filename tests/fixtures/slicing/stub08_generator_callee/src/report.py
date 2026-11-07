from rows import rows


def total(path):
    count = 0
    for row in rows(path, 10):
        count += 1
    return count
