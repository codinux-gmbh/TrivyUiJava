package net.codinux.trivy

enum class KubernetesClusterScanner(val scanner: String) {
    Vulnerabilities("vuln"),
    Misconfiguration("misconfig"),
    Secrets("secret"),
    RBAC("rbac")
}