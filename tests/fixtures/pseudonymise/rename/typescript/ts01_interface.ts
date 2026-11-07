interface Account {
  accountId: string;
  balance: number;
}

function describe(account: Account): string {
  return account.accountId;
}
