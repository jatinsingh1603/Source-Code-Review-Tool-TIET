def schedule(queue):
    prefix = 'job'

    def worker(item):
        name = prefix + item
        return eval(name)

    return [worker(i) for i in queue]
