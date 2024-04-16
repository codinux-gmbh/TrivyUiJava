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


    private val cachedClusterScanReports = ConcurrentHashMap<String, MutableMap<KubernetesScanner, KubernetesClusterReport>>()

    private val scanKubernetesClustersTimer = timer(period = 12 * 60 * 60 * 1000L) {
        scanAllKubernetesClusters()
    }

    private val log by logger()

    init {
        retrievePersistedState()
    }


    private fun scanAllKubernetesClusters() {
        log.info { "Scanning all Kubernetes clusters ..." }

        kubernetesClient.contextNames.forEach { context ->
            thread {
                try {
                    scanKubernetesCluster(context, KubernetesScanner.Vulnerabilities)
                    scanKubernetesCluster(context, KubernetesScanner.RBAC)
                    scanKubernetesCluster(context, KubernetesScanner.Secrets)
                    scanKubernetesCluster(context, KubernetesScanner.Misconfiguration)
                } catch (e: Throwable) {
                    log.error(e) { "Could not scan cluster '$context'" }
                }
            }
        }
    }


    fun getKubernetesClusterVulnerabilities(contextName: String? = null) =
        getKubernetesClusterScanReport(contextName, KubernetesScanner.Vulnerabilities)

    fun getKubernetesClusterMisconfiguration(contextName: String? = null) =
        getKubernetesClusterScanReport(contextName, KubernetesScanner.Misconfiguration)

    fun getKubernetesClusterExposedSecrets(contextName: String? = null) =
        getKubernetesClusterScanReport(contextName, KubernetesScanner.Secrets)

    fun getKubernetesClusterRbacMisconfiguration(contextName: String? = null) =
        getKubernetesClusterScanReport(contextName, KubernetesScanner.RBAC)

    private fun getKubernetesClusterScanReport(contextName: String?, scanner: KubernetesScanner): Pair<KubernetesClusterReport?, String?> {
        val contextNameKey = kubernetesClient.getNonNullContextName(contextName)

        cachedClusterScanReports[contextNameKey]?.get(scanner)?.let { scanReports ->
            return Pair(scanReports, null)
        }

        return scanKubernetesCluster(contextName ?: kubernetesClient.defaultContext, scanner)
    }

    private fun scanKubernetesCluster(contextName: String? = null, scanner: KubernetesScanner): Pair<KubernetesClusterReport?, String?> {
        val (jsonReport, clusterReport, error) = trivyClient.scanKubernetesCluster(contextName, reportType = ReportType.All, scanners = setOf(scanner))

        if (clusterReport != null) {
            val contextNameKey = kubernetesClient.getNonNullContextName(contextName)
            this.cachedClusterScanReports.getOrPut(contextNameKey, { ConcurrentHashMap() })[scanner] = clusterReport

            persistClusterState(contextNameKey, scanner, clusterReport)
        }

        return Pair(clusterReport, error)
    }


    fun getVulnerabilitiesOfImage(imageId: String): Pair<Report?, String?> {
        val cachedScanReport = cachedClusterScanReports.mapNotNull { it.value[KubernetesScanner.Vulnerabilities] }
            .flatMap { it.Resources }
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
                    val scanner = KubernetesScanner.valueOf(stateFile.nameWithoutExtension)
                    this.cachedClusterScanReports.getOrPut(contextName, { ConcurrentHashMap() })[scanner] = report
                }
            }
        } catch (e: Throwable) {
            log.error(e) { "Could not deserialize persisted vulnerabilities scan report" }
        }
    }

    private fun persistClusterState(contextName: String, scanner: KubernetesScanner, report: KubernetesClusterReport) {
        try {
            val outputFile = getClusterStateFile(contextName, scanner)

            objectMapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, report)
        } catch (e: Throwable) {
            log.error(e) { "Could not persist ${scanner.scanner} report of cluster '$contextName'" }
        }
    }

    private fun getClusterStateFile(contextName: String, scanner: KubernetesScanner) =
        File(getClusterStateDirectory(contextName), "${scanner.name.lowercase()}.json")

    private fun getClusterStateDirectory(contextName: String) =
        File(getKubernetesStateDirectory(), contextName).also {
            it.mkdirs()
        }

    private fun getKubernetesStateDirectory() =
        File(dataDirectory, "kubernetes")

}