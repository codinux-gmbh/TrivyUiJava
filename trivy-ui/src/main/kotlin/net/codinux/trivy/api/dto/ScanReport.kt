package net.codinux.trivy.api.dto

import java.time.Instant

data class ScanReport(
    val context: String?,
    val scanStart: Instant,
    val countScannedImages: Int,
    val countCriticalVulnerabilities: Int,
    val countHighVulnerabilities: Int,
    val countMediumVulnerabilities: Int,
    val countLowVulnerabilities: Int,
    val resources: List<ResourceVulnerabilitiesSummary>,
    val error: String? = null
)