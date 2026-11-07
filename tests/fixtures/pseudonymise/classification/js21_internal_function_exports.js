function accrueInterest(account, rate) {
  return account.balance * rate;
}

module.exports = { accrueInterest };
