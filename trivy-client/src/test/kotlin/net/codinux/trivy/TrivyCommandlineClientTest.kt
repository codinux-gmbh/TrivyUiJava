package net.codinux.trivy

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.hasSize
import assertk.assertions.isEqualByComparingTo
import assertk.assertions.isNotNull
import org.junit.jupiter.api.Test

/**
 * These tests assume that Trivy is installed and added to path.
 */
class TrivyCommandlineClientTest {

    private val underTest = TrivyCommandlineClient()


    @Test
    fun scanDockerImage() {
        val result = underTest.scanDockerImage("quay.io/keycloak/keycloak:24.0", ReportType.Summary, OutputFormat.Table)

        assertThat(result).isNotNull()
        assertThat(result!!).contains("quay.io/keycloak/keycloak:24.0 (redhat 9.3)")
        assertThat(result).contains("Total: 17 (UNKNOWN: 0, LOW: 17, MEDIUM: 0, HIGH: 0, CRITICAL: 0)")
    }

    @Test
    fun convertJsonReportToTable() {
        val jsonReport = underTest.scanDockerImage("quay.io/keycloak/keycloak:24.0", ReportType.Summary, OutputFormat.Json)

        val result = underTest.convertJsonReport(OutputFormat.Table, jsonReport!!)

        assertThat(result).isNotNull()
        assertThat(result!!).contains("quay.io/keycloak/keycloak:24.0 (redhat 9.3)")
        assertThat(result).contains("Total: 17 (UNKNOWN: 0, LOW: 17, MEDIUM: 0, HIGH: 0, CRITICAL: 0)")
    }

    @Test
    fun deserializeJsonReport() {
        val jsonReport = javaClass.classLoader.getResourceAsStream("jsonReports/vaultwarden-3.19.1.json")!!.reader().readText()

        val result = underTest.deserializeJsonReport(jsonReport)

        assertThat(result).isNotNull()
        assertThat(result!!.Results).hasSize(2)

        val secretsReport = result.Results[1]
        assertThat(secretsReport.Secrets).hasSize(1)

        val detectedSecrets = secretsReport.Secrets.first()
        assertThat(detectedSecrets.RuleID).isEqualByComparingTo("stripe-publishable-token")
        // TODO: why can't lines be deserialized?
//        assertThat(detectedSecrets.Code.Lines).hasSize(2)
    }

}