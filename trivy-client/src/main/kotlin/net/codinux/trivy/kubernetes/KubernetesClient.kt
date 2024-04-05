package net.codinux.trivy.kubernetes

interface KubernetesClient {

    fun getAllContainerImagesOfCluster(contextName: String? = null): Set<ContainerImage>

}