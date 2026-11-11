package com.bank.ledger;

public class Settlement {
    private long balance;

    public void apply(long balance) {
        long delta = balance - this.balance;
        this.balance = balance;
        for (int step = 0; step < 3; step++) {
            long balance2 = delta + step;
            this.balance += balance2;
        }
    }
}
