def route(kind, value, log):
    log.info('start')
    log.info(kind)
    if kind == 'a':
        log.info('a')
    elif kind == 'b':
        return eval(value)
    else:
        log.info('other')
    log.info('end')
    log.info('done')
    return None
