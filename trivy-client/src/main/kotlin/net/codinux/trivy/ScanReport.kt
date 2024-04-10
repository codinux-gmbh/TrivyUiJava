package net.codinux.trivy

import net.codinux.trivy.report.Report
import java.time.Instant

data class ScanReport(
    val startTime: Instant,
    val error: String?,
    val report: Report?,
    val reportJson: String?
)