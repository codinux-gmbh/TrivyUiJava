package net.codinux.trivy.api.dto

data class MisconfigurationScanReport(
    val context: String?,
    val successes: Int,
    val failures: Int,
    val exceptions: Int,
    val resourceMisconfigurations: List<ResourceMisconfigurations>
)