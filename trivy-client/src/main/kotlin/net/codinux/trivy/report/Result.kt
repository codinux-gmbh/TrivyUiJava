package net.codinux.trivy.report

data class Result(
    val Target: String,
    val Class: ResultClass? = null,
    val Type: String? = null, // TODO: is actually the value of 3 different enums: OSType, LnagType and ConfigType, see https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/types/const.go
    val Packages: List<Package> = emptyList(),
    val Vulnerabilities: List<DetectedVulnerability> = emptyList(),
    val MisconfSummary: MisconfSummary? = null,
    val Misconfigurations: List<DetectedMisconfiguration> = emptyList(),
    val Secrets: List<DetectedSecret> = emptyList(),
    val Licenses: List<DetectedLicense> = emptyList(),
    val CustomResources: List<CustomResource> = emptyList()
)
