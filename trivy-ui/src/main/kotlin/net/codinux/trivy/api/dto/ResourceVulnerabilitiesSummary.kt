package net.codinux.trivy.api.dto

data class ResourceVulnerabilitiesSummary(
    val namespace: String?,
    val kind: String,
    val name: String,
    val imageId: String? = null,
    val imageTags: List<String>,
    val scanner: String?,
    val countCriticalVulnerabilities: Int,
    val countHighVulnerabilities: Int,
    val countMediumVulnerabilities: Int,
    val countLowVulnerabilities: Int
)