package net.codinux.trivy.report

data class Resource(
    val Namespace: String? = null,
    val Kind: String,
    val Name: String,
    val Metadata: Metadata? = null,
    val Results: List<Result> = emptyList(),
    val Error: String? = null,
)