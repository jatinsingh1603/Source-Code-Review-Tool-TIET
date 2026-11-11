package com.bank.model;

public record Installment(long principal, int months) {
    public long monthly() {
        return principal / months;
    }
}

enum RiskBand {
    LOW, MEDIUM, HIGH;

    boolean flagged() {
        return this == HIGH;
    }
}
