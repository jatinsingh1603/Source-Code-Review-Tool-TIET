def read_ledger(path):
    with open(path) as ledger_file, open(path) as backup_file:
        return ledger_file.read() + backup_file.read()
