function settle(batch, ledger, audit) {
  let total = 0;
  for (const item of batch) {
    total += item.amount;
    audit.record(item.id, item.amount);
    audit.record(item.id, item.fee);
    audit.flush();
  }
  audit.record('summary', total);
  if (ledger.isOpen()) {
    if (total > 0) {
      ledger.append('INSERT INTO settled VALUES (' + total + ')');
    }
  }
  audit.record('done', total);
  audit.flush();
  audit.close();
  return total;
}
