from . import billing_rules
from .models import Account


def load(account_id):
    return billing_rules.apply(Account(account_id))
