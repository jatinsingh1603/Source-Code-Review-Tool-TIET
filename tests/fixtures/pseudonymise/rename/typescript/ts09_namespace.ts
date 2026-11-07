namespace Billing {
  export const taxRate = 18;
  export function applyTax(amount: number): number {
    return amount + taxRate;
  }
}
