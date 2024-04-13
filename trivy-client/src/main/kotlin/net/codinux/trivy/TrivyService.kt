package net.codinux.trivy

import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import net.codinux.log.logger
import net.codinux.trivy.json.DefaultObjectMapper
import net.codinux.trivy.kubernetes.ContainerImage
import net.codinux.trivy.kubernetes.Fabric8KubernetesClient
import net.codinux.trivy.kubernetes.KubernetesClient
import net.codinux.trivy.report.Report
import java.io.File
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.concurrent.timer

class TrivyService(
    private val trivyClient: TrivyClient = TrivyCommandlineClient(),
    private val kubernetesClient: KubernetesClient = Fabric8KubernetesClient(),
    private val dataDirectory: File = getDataDirInTempDirectory(),
    private val objectMapper: ObjectMapper = DefaultObjectMapper.mapper
) {

    companion object {

        fun getDataDirInTempDirectory(): File {
            val tmpFile = File.createTempFile("trivy-ui", "tmp")
            val tmpDir = tmpFile.parentFile
            tmpFile.delete()

            val dataDir = File(tmpDir, "trivy-ui")
            dataDir.mkdirs()

            return dataDir
        }

    }


    private val cachedClusterVulnerabilitiesScanReports = ConcurrentHashMap<String, List<ScanReport>>()

    private val scanKubernetesClustersTimer = timer(period = 12 * 60 * 60 * 1000L) {
        retrieveImageVulnerabilitiesOfAllKubernetesClusters()
    }

    private val log by logger()

    init {
        retrievePersistedState()
    }


    private fun retrieveImageVulnerabilitiesOfAllKubernetesClusters() {
        log.info { "Retrieving image vulnerabilities of all Kubernetes clusters ..." }

        kubernetesClient.contextNames.forEach { context ->
            thread {
                try {
                    this.cachedClusterVulnerabilitiesScanReports[context] = retrieveAllImageVulnerabilitiesOfKubernetesCluster(context)
                } catch (e: Throwable) {
                    log.error(e) { "Could not retrieve image vulnerabilities of cluster '$context'" }
                }
            }
        }
    }

    fun getAllImageVulnerabilitiesOfKubernetesCluster(contextName: String? = null): List<ScanReport> {
        val contextNameKey = kubernetesClient.getNonNullContextName(contextName)

        cachedClusterVulnerabilitiesScanReports[contextNameKey]?.let { scanReports ->
            return scanReports
        }

        return retrieveAllImageVulnerabilitiesOfKubernetesCluster(contextName ?: kubernetesClient.defaultContext).also {
            this.cachedClusterVulnerabilitiesScanReports[contextNameKey] = it
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

        persistClusterVulnerabilitiesState(contextName, reports)

        return reports
    }


    fun getVulnerabilitiesOfImage(imageId: String): Pair<Report?, String?> {
        val cachedScanReport = cachedClusterVulnerabilitiesScanReports.flatMap { it.value }
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


    private fun retrievePersistedState() {
        try {
            val objectMapper = objectMapper.copy().apply {
                // most properties of Trivy Report start with an upper case letter, but due to the default naming strategy of Jackson
                // during serialization all properties get renamed to start with a lower case letter. So to deserialize Trivy Report
                // that has been serialized with Jackson we have to make property name detection case insensitive
                // TODO: add @JsonProperty to all properties that start with an upper case letter
                this.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
            }
            getKubernetesStateDirectory().list()?.forEach { contextName ->
                val reports = objectMapper.readerForListOf(ScanReport::class.java).readValue<List<ScanReport>>(getClusterVulnerabilitiesStateFile(contextName))
                this.cachedClusterVulnerabilitiesScanReports[contextName] = reports
            }
        } catch (e: Throwable) {
            log.error(e) { "Could not deserialize persisted vulnerabilities scan report" }
        }
    }

    private fun persistClusterVulnerabilitiesState(contextName: String?, reports: List<ScanReport>) {
        try {
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(getClusterVulnerabilitiesStateFile(contextName), reports)
        } catch (e: Throwable) {
            log.error(e) { "Could not persist vulnerabilities state of cluster '$contextName'" }
        }
    }

    private fun getClusterVulnerabilitiesStateFile(contextName: String?) =
        File(getClusterStateDirectory(contextName), "vulnerabilities.json")

    private fun getClusterStateDirectory(contextName: String?) =
        File(getKubernetesStateDirectory(), kubernetesClient.getNonNullContextName(contextName)).also {
            it.mkdirs()
        }

    private fun getKubernetesStateDirectory() =
        File(dataDirectory, "kubernetes")

}