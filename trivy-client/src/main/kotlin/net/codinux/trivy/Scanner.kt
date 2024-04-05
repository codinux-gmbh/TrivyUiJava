package net.codinux.trivy

enum class Scanner(val scanner: String) {
    Vulnerabilites("vuln"),
    Misconfig("misconfig"),
    Secrets("secret"),
    License("license")
}