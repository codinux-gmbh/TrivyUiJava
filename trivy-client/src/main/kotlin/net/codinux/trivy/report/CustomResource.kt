package net.codinux.trivy.report

data class CustomResource(
    val Type: String,
    val FilePath: String,
    val Layer: Layer,
    /**
     * CustomResource holds the analysis result from a custom analyzer.
     * It is for extensibility and not used in OSS.
     */
    val Data: Any
)
