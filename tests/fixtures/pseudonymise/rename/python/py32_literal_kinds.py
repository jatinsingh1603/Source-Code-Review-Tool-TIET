def build_queries(customer_id):
    sql = "SELECT balance FROM accounts WHERE owner = %s"
    url = "https://bank.example.com/api/v1/accounts/42"
    path = "/var/data/ledgers/2024/main.csv"
    pattern = r"^ACC-[0-9]{6}$"
    message = "Dear customer, your festival bonus is ready"
    fmt = "Hello %s you owe %d"
    return sql, url, path, pattern, message, fmt
