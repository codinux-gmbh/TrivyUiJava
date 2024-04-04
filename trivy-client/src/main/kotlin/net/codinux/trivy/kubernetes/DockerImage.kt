package net.codinux.trivy.kubernetes

data class DockerImage(
    val imageName: String,
    val imageId: String,
    val imagePullSecrets: List<String> = emptyList()
)