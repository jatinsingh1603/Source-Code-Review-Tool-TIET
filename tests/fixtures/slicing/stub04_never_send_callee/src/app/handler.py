from vault.keys import load_key


def sign(message):
    key = load_key()
    return message + key
