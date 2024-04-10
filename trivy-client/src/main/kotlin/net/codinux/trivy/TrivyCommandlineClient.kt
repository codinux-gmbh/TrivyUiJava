package net.codinux.trivy

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import net.codinux.log.logger
import net.codinux.trivy.json.DefaultObjectMapper
import net.codinux.trivy.report.Report
import java.io.File
import kotlin.concurrent.thread

/**
 * This assumes that Trivy is installed and is added to path so that it can be called with 'trivy ...'
 */
class TrivyCommandlineClient(
    private val objectMapper: ObjectMapper = DefaultObjectMapper.mapper
) : TrivyClient {

    private val log by logger()

    override fun scanContainerImage(imageName: String, reportType: ReportType, outputFormat: OutputFormat, scanners: Collection<Scanner>): Pair<String?, String?> {
        return executeCommandIncludingErrorOutput(
            "Could not retrieve vulnerabilities of Container image '$imageName'",
            "trivy", "image", "--format", outputFormat.format, "--report", reportType.type, "--scanners", scanners.joinToString(",") { it.scanner }, imageName
        )
    }

    override fun deserializeJsonReport(jsonReport: String): Report? = try {
        objectMapper.readValue<Report>(jsonReport)
    } catch (e: Throwable) {
        log.error(e) { "Could not deserialize JSON report:\n${jsonReport.take(200)}" }
        null
    }

    override fun convertJsonReport(destinationFormat: OutputFormat, jsonReport: String): String? {
        val errorMessage = "Could not convert JSON report to '$destinationFormat'"

        try {
            val tmpFile = File.createTempFile("TrivyJsonReport", "json")
            tmpFile.deleteOnExit()
            tmpFile.writeText(jsonReport)

            return executeCommand(
                errorMessage,
                "trivy", "convert", "--format", destinationFormat.format, "--report", "all", tmpFile.path
            )
        } catch (e: Throwable) {
            log.error(e) { errorMessage }
            return null
        }
    }

    private fun executeCommand(errorMessage: String, vararg command: String): String? {
        val (result, _) = executeCommandIncludingErrorOutput(errorMessage, *command)

        return result
    }

    private fun executeCommandIncludingErrorOutput(errorMessage: String, vararg command: String): Pair<String?, String?> {
        try {
            val process = ProcessBuilder()
                .command(*command)
                .start()

            val errors = StringBuilder()
            thread {
                process.errorReader().forEachLine { errors.appendLine(it) }
            }

            val result = process.inputReader().readText()

            return if (result.isNotBlank()) {
                Pair(result, null)
            } else {
                log.error { "$errorMessage. Error messages:\n$errors" }
                Pair(null, errors.toString())
            }
        } catch (e: Throwable) {
            log.error(e) { errorMessage }
            return Pair(null, e.message)
        }
    }
}