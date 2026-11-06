import os

DEBUG = True
SIGNING_MODE = 'hmac'
DATABASE = os.environ.get('DB')

TIMEOUT = 30
RETRIES = 3

def helper():
    return 1
