package com.bank.util;

import static java.lang.Math.max;
import static com.bank.util.Rounding.roundHalfEven;

public class Fees {
    public long fee(long base, long floor) {
        return roundHalfEven(max(base, floor));
    }
}
