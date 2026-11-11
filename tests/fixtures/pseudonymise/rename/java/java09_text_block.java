package com.bank.reports;

public class Queries {
    public static final String STATEMENT = """
        SELECT festival_bonus, owner_name
        FROM accounts
        WHERE branch = 'andheri'
        """;
}
