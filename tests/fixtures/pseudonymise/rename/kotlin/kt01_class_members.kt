package com.thapar.payroll

class FestivalBonusCalculator(private val baseRate: Long, val schemeName: String) {
    private var accrued: Long = 0

    fun accrue(employeeCount: Int): Long {
        val gross = baseRate * employeeCount
        accrued += gross
        return accrued
    }

    fun describe(): String = "scheme " + schemeName + " accrued " + accrued
}
