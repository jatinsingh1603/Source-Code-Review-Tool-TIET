def load_premium(cur, customer_id):
    cur.execute("SELECT balance, festival_bonus FROM premium_accounts WHERE customer_id = '%s'")
    cur.execute("SELECT name FROM staff WHERE department_code = 7 AND salary > 90000")
    cur.execute("DELETE FROM audit_trail WHERE retention_days = 30")
    cur.execute("SELECT region_name FROM branch_offices WHERE branch_code = ? LIMIT 10")
    return cur.fetchall()
