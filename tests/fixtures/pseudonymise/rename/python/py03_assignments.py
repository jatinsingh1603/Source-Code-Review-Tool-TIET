def totals(items):
    running_total = 0
    count = 0
    for entry in items:
        running_total += entry.amount
        count += 1
    first, second = items[0], items[1]
    return running_total, count, first, second
