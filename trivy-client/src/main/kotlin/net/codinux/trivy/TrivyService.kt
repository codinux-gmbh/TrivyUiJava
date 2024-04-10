package net.codinux.trivy

import net.codinux.log.logger
import net.codinux.trivy.kubernetes.Fabric8KubernetesClient
import net.codinux.trivy.kubernetes.KubernetesClient
import net.codinux.trivy.report.Report
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class TrivyService(
    private val trivyClient: TrivyClient = TrivyCommandlineClient(),
    private val kubernetesClient: KubernetesClient = Fabric8KubernetesClient()
) {

    private var cachedVulnerabilitiesScanReports = ConcurrentHashMap<String, List<ScanReport>>()

    private val log by logger()

    init {
        kubernetesClient.contextNames.forEach { context ->
            thread {
                this.cachedVulnerabilitiesScanReports[context] = retrieveAllImageVulnerabilitiesOfKubernetesCluster(context)
            }
        }
    }

    fun getAllImageVulnerabilitiesOfKubernetesCluster(contextName: String? = null): List<ScanReport> {
        val contextNameKey = kubernetesClient.getNonNullContextName(contextName)

        cachedVulnerabilitiesScanReports[contextNameKey]?.let { scanReports ->
            return scanReports
        }

        return retrieveAllImageVulnerabilitiesOfKubernetesCluster(contextName ?: kubernetesClient.defaultContext).also {
            this.cachedVulnerabilitiesScanReports[contextNameKey] = it
        }
    }

    private fun retrieveAllImageVulnerabilitiesOfKubernetesCluster(contextName: String? = null): List<ScanReport> {
        val images = kubernetesClient.getAllContainerImagesOfCluster(contextName)

        val reports = CopyOnWriteArrayList<ScanReport>()
        val latch = CountDownLatch(images.size)

        images.map { image ->
            thread {
                val startTime = Instant.now()
                val (error, reportJson, report) = getVulnerabiliesOfImage(image.imageId)
                reports.add(ScanReport(image, startTime, error, report, reportJson))

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