package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue
import com.fasterxml.jackson.annotation.JsonValue

enum class Status(@JsonValue val status: String) {
    @JsonEnumDefaultValue
    Unknown("unknown"),
    NotAffected("not_affected"),
    Affected("affected"),
    Fixed("fixed"),
    UnderInvestigation("under_investigation"),
    WillNotFix("will_not_fix"),  // Red Hat specific
    FixDeferred("fix_deferred"),
    EndOfLife("end_of_life")
}