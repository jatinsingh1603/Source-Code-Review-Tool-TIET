def settle(batch):
    total = _sum_batch(batch)
    return total


def _sum_batch(batch):
    return sum(batch)
