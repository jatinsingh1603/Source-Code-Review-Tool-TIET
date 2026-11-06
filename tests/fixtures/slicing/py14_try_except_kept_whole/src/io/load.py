import pickle


def load(blob, log):
    log.info('loading')
    try:
        value = pickle.loads(blob)
    except Exception:
        log.error('bad blob')
        value = None
    log.info('loaded')
    return value
