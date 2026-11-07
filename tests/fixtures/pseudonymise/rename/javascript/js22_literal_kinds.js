function queries(customerId) {
  const sql = "SELECT balance FROM accounts WHERE owner = ?";
  const url = "https://bank.example.com/api/v1/accounts/42";
  const pattern = /^ACC-[0-9]{6}$/;
  const message = "Dear customer, your festival bonus is ready";
  return [sql, url, pattern, message];
}
