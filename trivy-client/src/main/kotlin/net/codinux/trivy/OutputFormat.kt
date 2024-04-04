package net.codinux.trivy

enum class OutputFormat(val format: String) {
    Table("table"),
    Json("json"),
//    Template("template"),
    Sarif("sarif"),
    CycloneDx("cyclonedx"),
    SpDx("spdx"),
    SpDxJson("spdx-json"),
    GitHub("github"),
    CosignVuln("cosign-vuln")
}