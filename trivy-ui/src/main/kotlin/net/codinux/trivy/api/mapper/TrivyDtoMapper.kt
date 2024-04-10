package net.codinux.trivy.api.mapper

import jakarta.inject.Singleton
import net.codinux.trivy.api.dto.ImageVulnerabilitiesSummary
import net.codinux.trivy.api.dto.ScanReport
import net.codinux.trivy.kubernetes.ContainerImage
import net.codinux.trivy.report.Report
import net.codinux.trivy.report.Severity
import java.time.Instant

@Singleton
class TrivyDtoMapper {

    fun mapToScanReport(context: String?, startTime: Instant, vulnerabilities: Map<ContainerImage, net.codinux.trivy.ScanReport>): ScanReport {
        val reports = vulnerabilities.values.map { it.report }.filterNotNull()

        return ScanReport(context, startTime, vulnerabilities.size, countSeverity(reports, Severity.Critical),
            countSeverity(reports, Severity.High), countSeverity(reports, Severity.Medium), countSeverity(reports, Severity.Low),
            vulnerabilities.map { mapToImageVulnerabilitiesOverview(it) }
        )
    }

    private fun mapToImageVulnerabilitiesOverview(imageToReport: Map.Entry<ContainerImage, net.codinux.trivy.ScanReport>): ImageVulnerabilitiesSummary {
        val image = imageToReport.key
        val report = imageToReport.value.report

        return ImageVulnerabilitiesSummary(
            "", image.imageName, image.imageId, "",
            countSeverity(report, Severity.Critical), countSeverity(report, Severity.High), countSeverity(report, Severity.Medium), countSeverity(report, Severity.Low)
        )
    }

    private fun countSeverity(reports: List<Report>, severity: Severity): Int =
        reports.sumOf { countSeverity(it, severity) }

    private fun countSeverity(report: Report?, severity: Severity): Int =
        report?.Results?.sumOf { it.Vulnerabilities.sumOf { it.VendorSeverity.entries.filter { it.value == severity }.size } }
            ?: 0

}