package net.codinux.trivy.kubernetes

import assertk.assertThat
import assertk.assertions.isNotEmpty
import org.junit.jupiter.api.Test

class Fabric8KubernetesClientTest {

    private val underTest = Fabric8KubernetesClient(KubeConfigsReader().getKubeConfigs())

    @Test
    fun getAllDockerImagesOfCluster() {

        val result = underTest.getAllDockerImagesOfCluster()

        assertThat(result).isNotEmpty()
    }
}