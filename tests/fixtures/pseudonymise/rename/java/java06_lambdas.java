package com.bank.jobs;

import java.util.List;
import java.util.stream.Collectors;

public class Totals {
    public long sumLarge(List<Long> amounts, long threshold) {
        return amounts.stream()
            .filter(amount -> amount > threshold)
            .map(amount -> amount * 2)
            .collect(Collectors.summingLong(Long::longValue));
    }
}
