package net.codinux.trivy.api.dto

data class SecretsScanReport(
    val context: String?,
//    val scanStart: Instant,
    val countScannedResources: Int,
    val countCriticalSeverities: Int,
    val countHighSeverities: Int,
    val countMediumSeverities: Int,
    val countLowSeverities: Int,
    val resources: List<ResourceSecretsScanSummary>
)