package net.codinux.trivy.report

data class Line(
    val Number: Int,
    val Content: String,
    val IsCause: Boolean,
    val Annotation: String,
    val Truncated: Boolean,
    val Highlighted: String? = null,
    val FirstCause: Boolean,
    val LastCause: Boolean
)
