package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue
import com.fasterxml.jackson.annotation.JsonValue

enum class Severity(@JsonValue val severity: String) {
    @JsonEnumDefaultValue
    Unknown("UNKNOWN"),
    Low("LOW"),
    Medium("MEDIUM"),
    High("HIGH"),
    Critical("CRITICAL")
}