def save(payload):
    path = "/data/" + payload
    return open(path, "w")
