package net.codinux.trivy

import net.codinux.trivy.report.Report

interface TrivyClient {

    companion object {
        val DefaultScanners = setOf(Scanner.Vulnerabilites, Scanner.Secrets)
    }

    fun scanContainerImage(
        imageName: String,
        reportType: ReportType = ReportType.Summary,
        outputFormat: OutputFormat = OutputFormat.Json,
        scanners: Collection<Scanner> = DefaultScanners
    ): String?

    fun deserializeJsonReport(jsonReport: String): Report?

    fun convertJsonReport(destinationFormat: OutputFormat, jsonReport: String): String?

}