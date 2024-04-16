package net.codinux.trivy.api.dto

data class ResourceSecretsScanSummary(
    val namespace: String?,
    val kind: String,
    val name: String,
    val imageId: String? = null,
    val imageTags: List<String>,
    val countCriticalSeverities: Int,
    val countHighSeverities: Int,
    val countMediumSeverities: Int,
    val countLowSeverities: Int
)