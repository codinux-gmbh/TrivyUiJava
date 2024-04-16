package net.codinux.trivy

import net.codinux.trivy.report.KubernetesClusterReport
import net.codinux.trivy.report.Report

interface TrivyClient {

    companion object {
        val DefaultScanners = setOf(Scanner.Vulnerabilities, Scanner.Secrets)
    }

    fun scanContainerImage(
        imageName: String,
        reportType: ReportType = ReportType.Summary,
        outputFormat: OutputFormat = OutputFormat.Json,
        scanners: Collection<Scanner> = DefaultScanners
    ): Pair<String?, String?>

    fun scanKubernetesCluster(
        contextName: String?,
        namespace: String? = null,
        scanAllNamespaces: Boolean = false,
        reportType: ReportType = ReportType.Summary,
        outputFormat: OutputFormat = OutputFormat.Json,
        listAllPackages: Boolean = false,
        scanners: Collection<KubernetesScanner> = setOf(KubernetesScanner.Vulnerabilities)
    ): Triple<String?, KubernetesClusterReport?, String?>


    fun deserializeJsonReport(jsonReport: String): Report?

    fun convertJsonReport(destinationFormat: OutputFormat, jsonReport: String): String?

}