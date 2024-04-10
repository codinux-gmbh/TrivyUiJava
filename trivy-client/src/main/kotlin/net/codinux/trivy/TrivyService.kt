package net.codinux.trivy

import net.codinux.log.logger
import net.codinux.trivy.kubernetes.ContainerImage
import net.codinux.trivy.kubernetes.Fabric8KubernetesClient
import net.codinux.trivy.kubernetes.KubernetesClient
import net.codinux.trivy.report.Report
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class TrivyService(
    private val trivyClient: TrivyClient = TrivyCommandlineClient(),
    private val kubernetesClient: KubernetesClient = Fabric8KubernetesClient()
) {

    private val log by logger()


    fun getAllImageVulnerabilitiesOfKubernetesCluster(contextName: String? = null): Map<ContainerImage, ScanReport> {
        val images = kubernetesClient.getAllContainerImagesOfCluster(contextName)

        val reports = mutableMapOf<ContainerImage, ScanReport>()
        val latch = CountDownLatch(images.size)

        images.map { image ->
            thread {
                val startTime = Instant.now()
                val (error, reportJson, report) = getVulnerabiliesOfImage(image.imageId)
                reports[image] = ScanReport(startTime, error, report, reportJson)

                latch.countDown()
            }
        }

        latch.await(10, TimeUnit.MINUTES)

        return reports
    }

    fun getVulnerabiliesOfImage(imageId: String): Triple<String?, String?, Report?> {
        try {
            val (jsonReport, error) = trivyClient.scanContainerImage(imageId, ReportType.All, OutputFormat.Json, setOf(Scanner.Vulnerabilites))

            if (jsonReport != null) {
                val report = trivyClient.deserializeJsonReport(jsonReport)

                return Triple(null, jsonReport, report)
            } else {
                return Triple(error, null, null)
            }
        } catch (e: Throwable) {
            log.error(e) { "Could not get vulnerabilities summary for image '$imageId'" }

            return Triple(e.message, null, null)
        }
    }

}