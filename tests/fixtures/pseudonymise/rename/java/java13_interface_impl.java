package com.bank.ledger;

public interface Posting {
    void post(long amount);
}

class CashPosting implements Posting, Comparable<CashPosting> {
    private long posted;

    @Override
    public void post(long amount) {
        posted += amount;
    }

    @Override
    public int compareTo(CashPosting other) {
        return Long.compare(posted, other.posted);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CashPosting cash && cash.posted == posted;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(posted);
    }
}
