package net.codinux.trivy.report

import java.time.Instant

data class Report(
    val SchemaVersion: Int? = null,
    val CreatedAt: Instant? = null,
    val ArtifactName: String? = null,
    val ArtifactType: String? = null, // see enum ArtifactType
    val Metadata: Metadata? = null,
    val Results: List<Result> = emptyList()
) {
}