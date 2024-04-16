package net.codinux.trivy.api.mapper

import jakarta.inject.Singleton
import net.codinux.trivy.api.dto.*
import net.codinux.trivy.report.*
import java.time.Instant

@Singleton
class TrivyDtoMapper {

    fun mapToVulnerabilitiesScanReport(context: String?, startTime: Instant, report: KubernetesClusterReport?, error: String?): VulnerabilitiesScanReport {
        return if (report == null) {
            VulnerabilitiesScanReport(context, startTime, 0, 0, 0, 0, 0, emptyList(), error)
        } else {
            val results = report.Resources.flatMap { it.Results }

            return VulnerabilitiesScanReport(context, startTime, results.size, countSeverity(results, Severity.Critical),
                countSeverity(results, Severity.High), countSeverity(results, Severity.Medium), countSeverity(results, Severity.Low),
                report.Resources.map { mapToResourceVulnerabilitiesSummary(it) }.sortedWith(compareBy( { it.namespace }, { it.kind }, { it.name } )) // TODO: it's not the backend's job to sort resources
            )
        }
    }

    private fun mapToResourceVulnerabilitiesSummary(resource: Resource): ResourceVulnerabilitiesSummary {
        val (imageId, imageTags) = getImageIdAndTags(resource)

        return ResourceVulnerabilitiesSummary(
            resource.Namespace, resource.Kind, resource.Name, imageId, imageTags, null,
            countSeverity(resource, Severity.Critical), countSeverity(resource, Severity.High), countSeverity(resource, Severity.Medium), countSeverity(resource, Severity.Low)
        )
    }

    private fun countSeverity(resource: Resource, severity: Severity): Int =
        countSeverity(resource.Results, severity)

    private fun countSeverity(results: List<Result>?, severity: Severity): Int =
        results?.sumOf { it.Vulnerabilities.count { it.Severity == severity.severity } }
            ?: 0



    fun mapToSecretsScanReport(context: String?, startTime: Instant, report: KubernetesClusterReport): SecretsScanReport {
        val resourceSecretsScanSummaries = report.Resources.map { resource ->
            val (imageId, imageTags) = getImageIdAndTags(resource)
            val detectedSecrets = resource.Results.flatMap { it.Secrets }

            ResourceSecretsScanSummary(resource.Namespace, resource.Kind, resource.Name, imageId, imageTags,
                countSecretSeverity(detectedSecrets, Severity.Critical), countSecretSeverity(detectedSecrets, Severity.High),
                countSecretSeverity(detectedSecrets, Severity.Medium), countSecretSeverity(detectedSecrets, Severity.Low))
        }

        return SecretsScanReport(context, report.Resources.size,
            resourceSecretsScanSummaries.sumOf { it.countCriticalSeverities }, resourceSecretsScanSummaries.sumOf { it.countHighSeverities },
            resourceSecretsScanSummaries.sumOf { it.countMediumSeverities }, resourceSecretsScanSummaries.sumOf { it.countLowSeverities },
            resourceSecretsScanSummaries.sortedWith(compareBy( { it.namespace }, { it.kind }, { it.name } )) // TODO: it's not the backend's job to sort resources
        )
    }

    private fun countSecretSeverity(secrets: List<DetectedSecret>?, severity: Severity): Int =
        secrets?.count { it.Severity == severity.severity }
            ?: 0


    fun mapToMisconfigurationScanReport(context: String?, startTime: Instant, report: KubernetesClusterReport): MisconfigurationScanReport {
        val resourceMisconfigurations = report.Resources.flatMap { resource ->
            resource.Results.filter { it.MisconfSummary != null }.map { result ->
                val summary = result.MisconfSummary!!

                ResourceMisconfigurations(resource.Namespace, resource.Kind, resource.Name, summary.Successes, summary.Failures, summary.Exceptions)
            }
        }

        return MisconfigurationScanReport(context, resourceMisconfigurations.sumOf { it.successes },
            resourceMisconfigurations.sumOf { it.failures }, resourceMisconfigurations.sumOf { it.exceptions },
            resourceMisconfigurations.sortedWith(compareBy( { it.namespace }, { it.kind }, { it.name } )) // TODO: it's not the backend's job to sort resources
        )
    }


    private fun getImageIdAndTags(resource: Resource): Pair<String?, List<String>> {
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

        return Pair(imageId, resource.Metadata?.RepoTags.orEmpty().map { it.replace("${imageName}:", "") })
    }

}