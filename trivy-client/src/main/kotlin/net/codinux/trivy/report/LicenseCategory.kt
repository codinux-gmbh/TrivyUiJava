package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue
import com.fasterxml.jackson.annotation.JsonValue

enum class LicenseCategory(@JsonValue val category: String) {
    Forbidden("forbidden"),
    Restricted("restricted"),
    Reciprocal("reciprocal"),
    Notice("notice"),
    Permissive("permissive"),
    Unencumbered("unencumbered"),
    @JsonEnumDefaultValue
    Unknown("unknown")
}