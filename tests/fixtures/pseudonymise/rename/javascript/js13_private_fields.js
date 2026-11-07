class Vault {
  #secretTotal = 0;
  static #instances = 0;

  add(amount) {
    this.#secretTotal += amount;
    return this.#secretTotal;
  }
}
