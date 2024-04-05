package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonProperty

data class RootFS(
    val type: String,
    @JsonProperty("diff_ids")
    //val diffIds: List<Hash>
    val diffIds: List<String>
)
