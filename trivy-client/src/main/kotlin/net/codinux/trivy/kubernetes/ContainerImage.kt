package net.codinux.trivy.kubernetes

data class ContainerImage(
    val imageName: String,
    val imageId: String,
    val imagePullSecrets: List<String> = emptyList()
)