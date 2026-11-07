function money(strings, amount) {
  return strings[0] + amount;
}

const price = 5;
const shown = money`total: ${price}`;
