export class LimitGuard extends Guard {
  private limit: number = 10;
  private strict = true;
  public owner: string;
  readonly name: string = "g";

  check(amount: number): boolean {
    if (amount > this.limit) {
      return this.refuse(amount);
    }
    return true;
  }

  private refuse(amount: number): boolean {
    return false;
  }
}
