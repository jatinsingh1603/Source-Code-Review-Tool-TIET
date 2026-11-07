const billing = require('billing-engine');

function run(account) {
  return billing.accrueInterest(account);
}
