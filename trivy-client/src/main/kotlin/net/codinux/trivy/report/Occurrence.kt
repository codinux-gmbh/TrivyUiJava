package net.codinux.trivy.report

data class Occurrence(
    val Resource: String? = null,
    val Filename: String? = null,
    val Location: Location
)
