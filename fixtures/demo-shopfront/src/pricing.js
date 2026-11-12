// Loyalty pricing: 5 percent off from 3 orders, 12 percent off from 10, capped at 40 currency units.
function loyaltyDiscount(orders, subtotal) {
  let rate = 0;
  if (orders >= 10) rate = 0.12;
  else if (orders >= 3) rate = 0.05;
  return Math.min(subtotal * rate, 40);
}
module.exports = { loyaltyDiscount };
