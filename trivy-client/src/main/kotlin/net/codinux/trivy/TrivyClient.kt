package net.codinux.trivy

interface TrivyClient {

    fun scanDockerImage(imageName: String, reportType: ReportType = ReportType.Summary, outputFormat: OutputFormat = OutputFormat.Json): String?

    fun convertJsonReport(destinationFormat: OutputFormat, jsonReport: String): String?

}