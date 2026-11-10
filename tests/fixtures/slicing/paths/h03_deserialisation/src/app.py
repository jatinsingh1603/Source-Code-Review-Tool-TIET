import pickle


def restore(blob):
    header = blob[:4]
    data = pickle.loads(blob[4:])
    return header, data
