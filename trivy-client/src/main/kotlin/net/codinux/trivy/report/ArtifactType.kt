package net.codinux.trivy.report

enum class ArtifactType(val type: String) {
    ContainerImage("container_image"),
    Filesystem("filesystem"),
    Repository("repository"),
    CycloneDX("cyclonedx"),
    SPDX("spdx"),
    AWSAccount("aws_account"),
    VM("vm")
}