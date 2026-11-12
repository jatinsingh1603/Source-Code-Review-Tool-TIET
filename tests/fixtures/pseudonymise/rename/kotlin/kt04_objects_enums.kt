package com.thapar.core

enum class RiskTier(val weight: Int) {
    LOWRISK(1), HIGHRISK(5)
}

object SessionRegistry {
    private val activeSessions = mutableMapOf<String, Long>()

    fun register(sessionToken: String, expiry: Long) {
        activeSessions[sessionToken] = expiry
    }
}

interface AuditSink {
    fun record(eventName: String)
}
