import logging

logger = logging.getLogger(__name__)


def a(password):
# ruleid: python.logging.sensitive-data
    logger.info("login %s", password)


def b(user_id):
# ok: python.logging.sensitive-data
    logger.info("login %s", user_id)
