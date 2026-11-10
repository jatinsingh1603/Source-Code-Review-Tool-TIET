function fetchRow(db, ledgerTable, accountId, status) {
  const query = "SELECT balance FROM " + ledgerTable + " WHERE id = '" + accountId + "'";
  db.query(query);
  db.query(`UPDATE ${ledgerTable} SET frozen_flag = 1 WHERE holder_ref = ${accountId}`);
  db.query("SELECT region_name FROM branch_offices " + "WHERE branch_code = " + accountId + " AND closing_status <> " + status);
  const note = "Tell the customer where the statement is kept";
  return [query, note];
}
