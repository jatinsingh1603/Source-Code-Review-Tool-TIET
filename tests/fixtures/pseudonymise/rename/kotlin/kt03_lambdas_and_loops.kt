package com.thapar.reports

fun summarise(ledgerLines: List<Int>): Int {
    var runningTotal = 0
    for (line in ledgerLines) {
        runningTotal += line
    }
    ledgerLines.forEach { entry -> runningTotal -= entry / 2 }
    val doubled = ledgerLines.map { value -> value * 2 }
    return runningTotal + doubled.size
}
