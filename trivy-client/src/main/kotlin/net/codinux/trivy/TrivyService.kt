package net.codinux.trivy

import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import net.codinux.log.logger
import net.codinux.trivy.json.DefaultObjectMapper
import net.codinux.trivy.kubernetes.Fabric8KubernetesClient
import net.codinux.trivy.kubernetes.KubernetesClient
import net.codinux.trivy.report.ArtifactType
import net.codinux.trivy.report.KubernetesClusterReport
import net.codinux.trivy.report.Report
import java.io.File
import java.util.concurrent.ConcurrentHashMap
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


    // TODO: convert to: Map<String, Map<KubernetesClusterScanner, KubernetesClusterReport>>
    private val cachedClusterVulnerabilitiesScanReports = ConcurrentHashMap<String, KubernetesClusterReport>()

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
                    scanKubernetesCluster(context, KubernetesClusterScanner.Vulnerabilities)
                } catch (e: Throwable) {
                    log.error(e) { "Could not retrieve image vulnerabilities of cluster '$context'" }
                }
            }
        }
    }

    fun getKubernetesClusterVulnerabilities(contextName: String? = null): Pair<KubernetesClusterReport?, String?> {
        val contextNameKey = kubernetesClient.getNonNullContextName(contextName)

        cachedClusterVulnerabilitiesScanReports[contextNameKey]?.let { scanReports ->
            return Pair(scanReports, null)
        }

        return scanKubernetesCluster(contextName ?: kubernetesClient.defaultContext, KubernetesClusterScanner.Vulnerabilities)
    }

    private fun scanKubernetesCluster(contextName: String? = null, scanner: KubernetesClusterScanner): Pair<KubernetesClusterReport?, String?> {

        val (jsonReport, clusterReport, error) = trivyClient.scanKubernetesCluster(contextName, reportType = ReportType.All, scanners = setOf(scanner))

        if (clusterReport != null) {
            val contextNameKey = kubernetesClient.getNonNullContextName(contextName)
            when (scanner) {
                KubernetesClusterScanner.Vulnerabilities -> this.cachedClusterVulnerabilitiesScanReports[contextNameKey] = clusterReport
            }
            persistClusterState(contextName, scanner, clusterReport)
        }

        return Pair(clusterReport, error)
    }


    fun getVulnerabilitiesOfImage(imageId: String): Pair<Report?, String?> {
        val cachedScanReport = cachedClusterVulnerabilitiesScanReports.flatMap { it.value.Resources }
            .firstOrNull { it.Metadata?.RepoDigests?.contains(imageId) == true }
        if (cachedScanReport != null) {
            val report = Report(null, null, cachedScanReport.Metadata?.RepoDigests?.firstOrNull(), ArtifactType.ContainerImage.type, cachedScanReport.Metadata, cachedScanReport.Results)
            return Pair(report, cachedScanReport.Error)
        }

        val (error, _, report) = fetchVulnerabilitiesOfImage(imageId)

        return Pair(report, error)
    }

    private fun fetchVulnerabilitiesOfImage(imageId: String): Triple<String?, String?, Report?> {
        try {
            val (jsonReport, error) = trivyClient.scanContainerImage(imageId, ReportType.All, OutputFormat.Json, setOf(Scanner.Vulnerabilities))

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

            getKubernetesStateDirectory().listFiles()?.forEach { contextDirectory ->
                val contextName = contextDirectory.name
                contextDirectory.listFiles()?.forEach { stateFile ->
                    val report = objectMapper.readValue<KubernetesClusterReport>(stateFile)
                    when (stateFile.nameWithoutExtension) {
                        KubernetesClusterScanner.Vulnerabilities.name.lowercase() -> this.cachedClusterVulnerabilitiesScanReports[contextName] = report
                    }
                }
            }
        } catch (e: Throwable) {
            log.error(e) { "Could not deserialize persisted vulnerabilities scan report" }
        }
    }

    private fun persistClusterState(contextName: String?, scanner: KubernetesClusterScanner, report: KubernetesClusterReport) {
        try {
            val outputFile = getClusterStateFile(contextName, scanner)

            objectMapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, report)
        } catch (e: Throwable) {
            log.error(e) { "Could not persist ${scanner.scanner} report of cluster '$contextName'" }
        }
    }

    private fun getClusterStateFile(contextName: String?, scanner: KubernetesClusterScanner) =
        File(getClusterStateDirectory(contextName), "${scanner.name.lowercase()}.json")

    private fun getClusterStateDirectory(contextName: String?) =
        File(getKubernetesStateDirectory(), kubernetesClient.getNonNullContextName(contextName)).also {
            it.mkdirs()
        }

    private fun getKubernetesStateDirectory() =
        File(dataDirectory, "kubernetes")

}