def fetch_row(cur, ledger_table, account_id, status):
    query = "SELECT balance FROM " + ledger_table + " WHERE id = '" + account_id + "'"
    cur.execute(query)
    cur.execute(
        "SELECT region_name FROM branch_offices "
        + "WHERE branch_code = " + account_id
        + " AND closing_status <> " + status
    )
    cur.execute(f"UPDATE {ledger_table} SET frozen_flag = 1 WHERE holder_ref = {account_id}")
    cur.execute("SELECT 1 " "FROM dual " "WHERE nominal_rate > 5")
    note = "Tell the customer where the statement is kept"
    return query, note
