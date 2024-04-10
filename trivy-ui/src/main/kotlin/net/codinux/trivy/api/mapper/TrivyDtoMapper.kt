package net.codinux.trivy.api.mapper

import jakarta.inject.Singleton
import net.codinux.trivy.api.dto.ImageVulnerabilitiesSummary
import net.codinux.trivy.api.dto.ScanReport
import net.codinux.trivy.report.Report
import net.codinux.trivy.report.Severity
import java.time.Instant

@Singleton
class TrivyDtoMapper {

    fun mapToScanReport(context: String?, startTime: Instant, scanReports: List<net.codinux.trivy.ScanReport>): ScanReport {
        val reports = scanReports.mapNotNull { it.report }

        return ScanReport(context, startTime, scanReports.size, countSeverity(reports, Severity.Critical),
            countSeverity(reports, Severity.High), countSeverity(reports, Severity.Medium), countSeverity(reports, Severity.Low),
            scanReports.map { mapToImageVulnerabilitiesOverview(it) }
        )
    }

    private fun mapToImageVulnerabilitiesOverview(imageToReport: net.codinux.trivy.ScanReport): ImageVulnerabilitiesSummary {
        val image = imageToReport.image
        val report = imageToReport.report

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