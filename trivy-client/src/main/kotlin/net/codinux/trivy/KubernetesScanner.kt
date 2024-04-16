package net.codinux.trivy

enum class KubernetesScanner(val scanner: String) {
    Vulnerabilities("vuln"),
    Misconfiguration("misconfig"),
    Secrets("secret"),
    RBAC("rbac")
}