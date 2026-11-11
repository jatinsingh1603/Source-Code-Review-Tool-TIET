package com.kavachbank.loans;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class LoanDisbursement {
    private final long festivalBonus;

    public LoanDisbursement(long festivalBonus) {
        this.festivalBonus = festivalBonus;
    }

    public long disburse(Connection connection, String borrowerRef) throws Exception {
        try (PreparedStatement statement =
                 connection.prepareStatement("select limit_amount from loans where ref = ?")) {
            statement.setString(1, borrowerRef);
            return statement.executeQuery().getLong("limit_amount") + festivalBonus;
        }
    }
}
