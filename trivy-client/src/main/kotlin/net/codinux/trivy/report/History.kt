package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class History(
    val author: String? = null,
    val created: Instant? = null,
    @JsonProperty("created_by")
    val createdBy: String? = null,
    val comment: String? = null,
    @JsonProperty("empty_layer")
    val emptyLayer: Boolean? = null
)
