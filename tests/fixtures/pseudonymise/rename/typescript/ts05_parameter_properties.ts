class Service {
  constructor(private store: string, public readonly region: string) {}

  describe(): string {
    return this.store + this.region;
  }
}
