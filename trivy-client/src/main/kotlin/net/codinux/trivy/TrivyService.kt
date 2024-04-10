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
import kotlin.concurrent.timer

class TrivyService(
    private val trivyClient: TrivyClient = TrivyCommandlineClient(),
    private val kubernetesClient: KubernetesClient = Fabric8KubernetesClient()
) {

    private val cachedVulnerabilitiesScanReports = ConcurrentHashMap<String, List<ScanReport>>()

    private val scanKubernetesClustersTimer = timer(period = 12 * 60 * 60 * 1000L) {
        retrieveImageVulnerabilitiesOfAllKubernetesClusters()
    }

    private val log by logger()


    private fun retrieveImageVulnerabilitiesOfAllKubernetesClusters() {
        log.info { "Retrieving image vulnerabilities of all Kubernetes clusters ..." }

        kubernetesClient.contextNames.forEach { context ->
            thread {
                try {
                    this.cachedVulnerabilitiesScanReports[context] = retrieveAllImageVulnerabilitiesOfKubernetesCluster(context)
                } catch (e: Throwable) {
                    log.error(e) { "Could not retrieve image vulnerabilities of cluster '$context'" }
                }
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
                val (error, reportJson, report) = fetchVulnerabilitiesOfImage(image.imageId)
                reports.add(ScanReport(image, startTime, error, report, reportJson))

                latch.countDown()
            }
        }

        latch.await(10, TimeUnit.MINUTES)

        return reports
    }


    fun getVulnerabilitiesOfImage(imageId: String): Pair<Report?, String?> {
        val cachedScanReport = cachedVulnerabilitiesScanReports.flatMap { it.value }
            .firstOrNull { it.image.imageId == imageId }
        if (cachedScanReport != null) {
            return Pair(cachedScanReport.report, cachedScanReport.error)
        }

        val (error, _, report) = fetchVulnerabilitiesOfImage(imageId)

        return Pair(report, error)
    }

    private fun fetchVulnerabilitiesOfImage(imageId: String): Triple<String?, String?, Report?> {
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