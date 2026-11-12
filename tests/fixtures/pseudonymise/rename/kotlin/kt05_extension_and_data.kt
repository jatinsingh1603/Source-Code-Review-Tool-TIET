package com.thapar.models

data class StudentRecord(val rollNumber: String, val cgpaScore: Double)

fun StudentRecord.isEligible(threshold: Double): Boolean {
    return cgpaScore >= threshold
}

fun topper(records: List<StudentRecord>): StudentRecord? {
    var best: StudentRecord? = null
    for (candidate in records) {
        if (best == null || candidate.cgpaScore > best.cgpaScore) {
            best = candidate
        }
    }
    return best
}
