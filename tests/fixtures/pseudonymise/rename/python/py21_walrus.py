def first_big(rows):
    if (found_row := next((r for r in rows if r > 10), None)) is not None:
        return found_row
