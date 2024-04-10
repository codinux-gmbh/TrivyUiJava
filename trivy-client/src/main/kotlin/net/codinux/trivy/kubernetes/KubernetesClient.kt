package net.codinux.trivy.kubernetes

interface KubernetesClient {

    val defaultContext: String?

    val contextNames: List<String>

    /**
     * ConcurrentHashMap throws an error on null keys, so if there's no context name available, e.g. in Kubernetes clusters,
     * this method returns a unique non-null default value, which cannot be used for real context names.
     */
    fun getNonNullContextName(contextName: String?): String

    fun getAllContainerImagesOfCluster(contextName: String? = null): Set<ContainerImage>

}