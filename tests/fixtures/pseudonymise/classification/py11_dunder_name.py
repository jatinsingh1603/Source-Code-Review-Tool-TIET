class Ledger:
    def __init__(self, entries):
        self.entries = entries

    def __repr__(self):
        return f"Ledger({len(self.entries)})"
