package net.codinux.trivy

import net.codinux.trivy.kubernetes.ContainerImage
import net.codinux.trivy.report.Report
import java.time.Instant

data class ScanReport(
    val image: ContainerImage,
    val startTime: Instant,
    val error: String?,
    val report: Report?,
    val reportJson: String?
)