package net.codinux.trivy.report

data class CauseMetadata(
    val Resource: String? = null,
    val Provider: String? = null,
    val Service: String? = null,
    val StartLine: Int? = null,
    val EndLine: Int? = null,
    val Code: Code? = null,
    val Occurrences: List<Occurrence> = emptyList()
)
