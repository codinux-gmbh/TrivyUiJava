package net.codinux.trivy.report

data class MisconfSummary(
    val Successes: Int,
    val Failures: Int,
    val Exceptions: Int
)
