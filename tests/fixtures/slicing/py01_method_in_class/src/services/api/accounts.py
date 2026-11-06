import os
from flask import route
import json


class AccountService:
    def __init__(self, db):
        self.db = db

    @route("/accrue")
    def accrue(self, account_id):
        rate = os.environ.get("RATE")
        cur = self.db.cursor()
        cur.execute("SELECT * FROM premium_accounts WHERE id = '%s'" % account_id)
        return cur.fetchall()

    def close(self):
        self.db.close()
