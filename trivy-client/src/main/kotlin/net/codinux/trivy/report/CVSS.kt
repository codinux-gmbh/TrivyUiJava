package net.codinux.trivy.report

data class CVSS(
    val V2Vector: String? = null,
    val V3Vector: String? = null,
    val V2Score: Double? = null,
    val V3Score: Double? = null
)
