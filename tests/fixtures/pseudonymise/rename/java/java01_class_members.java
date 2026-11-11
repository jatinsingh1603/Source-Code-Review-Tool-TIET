package com.bank.ledger;

public class FestivalAccount {
    private long festivalBonus;
    private String ownerName;

    public FestivalAccount(String ownerName, long festivalBonus) {
        this.ownerName = ownerName;
        this.festivalBonus = festivalBonus;
    }

    public long accrue(long rate) {
        long interest = festivalBonus * rate;
        return interest + 1;
    }

    public String getOwnerName() {
        return ownerName;
    }
}
