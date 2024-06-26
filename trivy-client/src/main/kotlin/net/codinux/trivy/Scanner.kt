package net.codinux.trivy

enum class Scanner(val scanner: String) {
    Vulnerabilities("vuln"),
    Misconfiguration("misconfig"),
    Secrets("secret"),
    License("license")
}