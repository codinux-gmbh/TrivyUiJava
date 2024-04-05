package net.codinux.trivy

import net.codinux.trivy.report.Report

interface TrivyClient {

    fun scanDockerImage(imageName: String, reportType: ReportType = ReportType.Summary, outputFormat: OutputFormat = OutputFormat.Json): String?

    fun deserializeJsonReport(jsonReport: String): Report?

    fun convertJsonReport(destinationFormat: OutputFormat, jsonReport: String): String?

}