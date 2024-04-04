package net.codinux.trivy.kubernetes

import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.KubernetesClientBuilder
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

class Fabric8KubernetesClient(
    private val kubeConfigs: KubeConfigs
) : net.codinux.trivy.kubernetes.KubernetesClient {

    companion object {
        val NonNullDefaultContextName = "__<default>__"
    }


    private val clientForContext = ConcurrentHashMap<String, KubernetesClient>()


    override fun getAllDockerImagesOfCluster(contextName: String?): Set<DockerImage> {
        val client = getClient(contextName)

        val secrets = client.secrets().inAnyNamespace().list().items.orEmpty()
            .filter { it.type == "kubernetes.io/dockerconfigjson" }
            .groupBy { it.metadata.namespace }
            .mapValues { it.value.mapNotNull { secret -> secret.data[".dockerconfigjson"]?.let { dockerConfigJson ->
                secret.metadata.name to String(Base64.getDecoder().decode(dockerConfigJson))
            } }.toMap() }

        // TODO: also get the images of Deployments, StatefulSets, ... that are scaled to 0? So that before they are
        //  upscaled that it's already clear if they contain vulnerabilities or not
        val images = client.pods().inAnyNamespace().list().items.orEmpty().flatMap { pod ->
            val pullSecrets = pod.spec.imagePullSecrets.orEmpty().mapNotNull {
                secrets[pod.metadata.namespace]?.get(it.name)
            }

            pod.status.containerStatuses.orEmpty().map { containerStatus ->
                DockerImage(containerStatus.image, containerStatus.imageID, pullSecrets)
            }
        }

        return images.toSet()
    }


    private fun getClient(contextName: String?): KubernetesClient {
        val contextToSearch = contextName ?: kubeConfigs.defaultContext ?: NonNullDefaultContextName // ConcurrentHashMap throws an error on null keys

        return clientForContext.getOrPut(contextToSearch) {
            if (contextToSearch == NonNullDefaultContextName) { // e.g. in Kubernetes clusters there is no context available
                KubernetesClientBuilder().build()
            } else {
                KubernetesClientBuilder().withConfig(kubeConfigs.getConfigForContext(contextToSearch)).build()
            }
        }
    }

}