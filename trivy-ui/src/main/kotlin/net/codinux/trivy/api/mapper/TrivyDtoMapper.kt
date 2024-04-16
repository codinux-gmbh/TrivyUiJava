package net.codinux.trivy.api.mapper

import jakarta.inject.Singleton
import net.codinux.trivy.api.dto.ResourceVulnerabilitiesSummary
import net.codinux.trivy.api.dto.ScanReport
import net.codinux.trivy.report.*
import java.time.Instant

@Singleton
class TrivyDtoMapper {

    fun mapToScanReport(context: String?, startTime: Instant, report: KubernetesClusterReport?, error: String?): ScanReport {
        return if (report == null) {
            ScanReport(context, startTime, 0, 0, 0, 0, 0, emptyList(), error)
        } else {
            val results = report.Resources.flatMap { it.Results }

            return ScanReport(context, startTime, results.size, countSeverity(results, Severity.Critical),
                countSeverity(results, Severity.High), countSeverity(results, Severity.Medium), countSeverity(results, Severity.Low),
                report.Resources.map { mapToResourceVulnerabilitiesSummary(it) }.sortedWith(compareBy( { it.namespace }, { it.kind }, { it.name } )) // TODO: it's not the backend's job to sort resources
            )
        }
    }

    private fun mapToResourceVulnerabilitiesSummary(resource: Resource): ResourceVulnerabilitiesSummary {
        val imageId = resource.Metadata?.RepoDigests?.firstOrNull()
        var imageName = imageId ?: ""
        val indexOfAt = imageName.indexOf('@')
        if (indexOfAt > -1) {
            imageName = imageName.substring(0, indexOfAt)
        }
        val indexOfColon = imageName.indexOf(':')
        if (indexOfColon > -1) {
            imageName = imageName.substring(0, indexOfColon)
        }

        return ResourceVulnerabilitiesSummary(
            resource.Namespace, resource.Kind, resource.Name, imageId, resource.Metadata?.RepoTags.orEmpty().map { it.replace("${imageName}:", "") }, null,
            countSeverity(resource, Severity.Critical), countSeverity(resource, Severity.High), countSeverity(resource, Severity.Medium), countSeverity(resource, Severity.Low)
        )
    }

    private fun countSeverity(resource: Resource, severity: Severity): Int =
        countSeverity(resource.Results, severity)

    private fun countSeverity(results: List<Result>?, severity: Severity): Int =
        results?.sumOf { it.Vulnerabilities.count { it.Severity == severity.severity } }
            ?: 0

}