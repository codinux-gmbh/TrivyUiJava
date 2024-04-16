package net.codinux.trivy.api.dto

data class ResourceMisconfigurations(
    val namespace: String?,
    val kind: String,
    val name: String,
    val successes: Int,
    val failures: Int,
    val exceptions: Int
)