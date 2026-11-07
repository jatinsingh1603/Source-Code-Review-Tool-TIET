def big_function(items):
    total = 0
    for item in items:
        if item.kind == "a":
            total += item.amount * 2
        elif item.kind == "b":
            total += item.amount * 3
        else:
            total += item.amount
    result = []
    for item in items:
        result.append(item.name.upper() + str(total))
    return result, total
