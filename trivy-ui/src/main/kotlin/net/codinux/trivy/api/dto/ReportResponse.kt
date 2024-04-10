package net.codinux.trivy.api.dto

import net.codinux.trivy.report.Report

data class ReportResponse(
    val error: String?,
    val report: Report?
)