class LedgerService:
    region: str = "south"
    tier_cap: int = 5
    floor: int = 1
    owner = None
    batch_size: int = 50
    audit_enabled: bool = True

    def __init__(self, ledger):
        self.ledger = ledger
        self.retries: int = 3

    def post(self, entry):
        if entry.amount > self.tier_cap:
            raise ValueError("too large")
        return self.ledger.append(entry)

    def reconcile(self):
        return self.batch_size
