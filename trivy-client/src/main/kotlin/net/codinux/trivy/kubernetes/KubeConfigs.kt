package net.codinux.trivy.kubernetes

import io.fabric8.kubernetes.client.Config

data class KubeConfigs(
    val defaultContext: String?,
    private val contextConfigs: Map<String, Config>
) {

    val contextNames: List<String> = contextConfigs.keys.sorted()

    fun getConfigForContext(contextName: String): Config? =
        contextConfigs[contextName]

}