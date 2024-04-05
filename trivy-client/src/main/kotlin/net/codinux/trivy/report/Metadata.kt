package net.codinux.trivy.report

data class Metadata(
    val Size: Long? = null,
    val OS: OS? = null,
    val ImageID: String? = null,
    val DiffIDs: List<String> = emptyList(),
    val RepoTags: List<String> = emptyList(),
    val RepoDigests: List<String> = emptyList(),
    val ImageConfig: ConfigFile? = null
)
