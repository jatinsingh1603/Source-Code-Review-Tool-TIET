class Account {
  constructor(id) {
    this.festivalRate = 1;
    this.id = id;
  }

  bonus() {
    return this.festivalRate;
  }
}
