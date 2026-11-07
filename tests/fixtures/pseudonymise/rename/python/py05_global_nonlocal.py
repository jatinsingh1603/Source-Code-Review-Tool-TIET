tally_count = 0


def bump():
    global tally_count
    tally_count += 1


def outer():
    inner_total = 0

    def add(delta):
        nonlocal inner_total
        inner_total += delta

    return add
