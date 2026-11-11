package com.bank.util;

import java.util.List;
import java.util.function.Function;

public class Ledger<Entry extends Comparable<Entry>> {
    private final List<Entry> entries;

    public Ledger(List<Entry> entries) {
        this.entries = entries;
    }

    public <Result> List<Result> project(Function<Entry, Result> mapper) {
        return entries.stream().map(mapper).toList();
    }
}
