package net.codinux.trivy.report

data class DetectedSecret(
    val RuleID: String,
    val Category: String, // TODO: actually SecretRuleCategory
    val Severity: String,
    val Title: String,
    val StartLine: Int,
    val EndLine: Int,
    val Code: Code,
    val Match: String,
    val Layer: Layer? = null
)
