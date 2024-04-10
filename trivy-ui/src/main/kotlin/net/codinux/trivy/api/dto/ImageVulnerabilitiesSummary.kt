package net.codinux.trivy.api.dto

data class ImageVulnerabilitiesSummary(
    val namespace: String,
    val name: String,
    val imageId: String,
    val scanner: String,
    val countCriticalVulnerabilities: Int,
    val countHighVulnerabilities: Int,
    val countMediumVulnerabilities: Int,
    val countLowVulnerabilities: Int
)