package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue
import com.fasterxml.jackson.annotation.JsonValue

enum class ResultClass(@JsonValue val value: String) {
    @JsonEnumDefaultValue
    Unknown("unknown"),
    OSPkg("os-pkgs"), // For detected packages and vulnerabilities in OS packages
    LangPkg("lang-pkgs"), // For detected packages and vulnerabilities in language-specific packages
    Config("config"), // For detected misconfigurations
    Secret("secret"), // For detected secrets
    License("license"), // For detected package licenses
    LicenseFile("license-file"), // For detected licenses in files
    Custom("custom")
}
