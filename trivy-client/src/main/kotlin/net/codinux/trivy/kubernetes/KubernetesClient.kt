package net.codinux.trivy.kubernetes

interface KubernetesClient {

    fun getAllDockerImagesOfCluster(contextName: String? = null): Set<DockerImage>

}