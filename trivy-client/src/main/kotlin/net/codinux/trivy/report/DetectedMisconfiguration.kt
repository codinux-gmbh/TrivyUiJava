package net.codinux.trivy.report

data class DetectedMisconfiguration(
    val Type: String? = null,
    val ID: String? = null,
    val AVDID: String? = null,
    val Title: String? = null,
    val Description: String? = null,
    val Message: String? = null,
    val Namespace: String? = null,
    val Query: String? = null,
    val Resolution: String? = null,
    val Severity: String? = null,
    val PrimaryURL: String? = null,
    val References: List<String> = emptyList(),
    val Status: String? = null, // PASS, FAIL or EXCEPTION, see https://github.com/aquasecurity/trivy/blob/main/pkg/types/misconfiguration.go#L28
    val Layer: Layer? = null,
    val CauseMetadata: CauseMetadata? = null,
    val Traces: List<String> = emptyList()
)
