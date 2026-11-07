function settleBatch(ledgerRef, amount) {
  return ledgerRef + amount;
}

const compute = function computeFee(baseAmount) {
  return baseAmount * 2;
};
