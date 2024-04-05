package net.codinux.trivy.report

// BuildInfo represents information under /root/buildinfo in RHEL
data class BuildInfo(
    val ContentSets: List<String> = emptyList(),
    val Nvr: String? = null,
    val Arch: String? = null
)
