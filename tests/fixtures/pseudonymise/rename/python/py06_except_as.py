def safe_div(numerator, denominator):
    try:
        return numerator / denominator
    except ZeroDivisionError as div_err:
        log_failure(div_err)
        raise
