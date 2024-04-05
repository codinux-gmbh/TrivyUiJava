package net.codinux.trivy.kubernetes

import assertk.assertThat
import assertk.assertions.isNotEmpty
import org.junit.jupiter.api.Test

class Fabric8KubernetesClientTest {

    private val underTest = Fabric8KubernetesClient(KubeConfigsReader().getKubeConfigs())

    @Test
    fun getAllContainerImagesOfCluster() {

        val result = underTest.getAllContainerImagesOfCluster()

        assertThat(result).isNotEmpty()
    }
}