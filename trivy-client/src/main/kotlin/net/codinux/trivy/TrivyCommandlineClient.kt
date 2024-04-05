package net.codinux.trivy

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import net.codinux.log.logger
import net.codinux.trivy.report.Report
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * This assumes that Trivy is installed and is added to path so that it can be called with 'trivy ...'
 */
class TrivyCommandlineClient : TrivyClient {

    private val objectMapper = ObjectMapper().apply {
        this.registerModules(
            JavaTimeModule(),
            KotlinModule.Builder().build()
        )

        this.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
    }

    private val log by logger()

    override fun scanDockerImage(imageName: String, reportType: ReportType, outputFormat: OutputFormat): String? {
        return executeCommand(
            "Could not retrieve vulnerabilities of Docker image '$imageName'",
            "trivy", "image", "--format", outputFormat.format, "--report", reportType.type, imageName
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

            val result = StringBuilder()
            val errors = StringBuilder()
            thread {
                process.inputReader().forEachLine { result.appendLine(it) }
            }
            thread {
                process.errorReader().forEachLine { errors.appendLine(it) }
            }

//            val result = process.inputReader().readText()
            process.waitFor(1, TimeUnit.MINUTES)

            if (result.isNotBlank()) {
                return Pair(result.toString(), null)
            } else {
                log.error { "$errorMessage. Process exit code ${process.exitValue()}, error messages:\n$errors" }
                return Pair(null, errors.toString())
            }
        } catch (e: Throwable) {
            log.error(e) { errorMessage }
            return Pair(null, e.message)
        }
    }
}