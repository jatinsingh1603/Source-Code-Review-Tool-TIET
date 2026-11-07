class AccountService:
    interest_rate = 3

    def __init__(self, store):
        self.store = store

    @classmethod
    def create(cls, store):
        return cls(store)

    @staticmethod
    def round_cents(value):
        return round(value)

    def accrue(self, account_id):
        return self.store.balance_of(account_id) * self.interest_rate
