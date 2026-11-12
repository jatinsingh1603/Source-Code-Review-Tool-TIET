package com.thapar.accounts

import java.sql.Connection

class AccountDao(private val connection: Connection) {
    fun findByOwner(ownerRef: String): List<String> {
        val query = "SELECT ref FROM accounts WHERE owner = '" + ownerRef + "'"
        val rows = connection.createStatement().executeQuery(query)
        val found = mutableListOf<String>()
        while (rows.next()) {
            found.add(rows.getString("ref"))
        }
        return found
    }
}
