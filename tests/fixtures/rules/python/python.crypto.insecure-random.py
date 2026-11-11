import random
import secrets


def make_token():
# ruleid: python.crypto.insecure-random
    return random.getrandbits(64)


def make_token_safe():
# ok: python.crypto.insecure-random
    return secrets.token_hex(16)


def shuffle_cards(cards):
# ok: python.crypto.insecure-random
    return random.choice(cards)
