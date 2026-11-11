package com.bank.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AccountDao {
    public long balanceOf(Connection connection, String accountRef) throws SQLException {
        try (PreparedStatement statement =
                 connection.prepareStatement("select balance from accounts where ref = ?")) {
            statement.setString(1, accountRef);
            ResultSet rows = statement.executeQuery();
            return rows.next() ? rows.getLong("balance") : 0L;
        }
    }
}
