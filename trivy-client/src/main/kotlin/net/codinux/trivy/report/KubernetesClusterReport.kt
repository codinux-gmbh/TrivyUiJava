package net.codinux.trivy.report

// see https://github.com/aquasecurity/trivy/blob/main/pkg/k8s/report/report.go#L41
data class KubernetesClusterReport(
    val SchemaVersion: Int? = null,
    val ClusterName: String,
    val name: String? = null,
    val Resources: List<Resource>,
)