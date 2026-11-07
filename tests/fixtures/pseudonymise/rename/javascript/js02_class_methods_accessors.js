class AccountService {
  constructor(store) {
    this.store = store;
  }

  get outstanding() {
    return this.store.total;
  }

  set outstanding(value) {
    this.store.total = value;
  }

  static create(store) {
    return new AccountService(store);
  }
}
