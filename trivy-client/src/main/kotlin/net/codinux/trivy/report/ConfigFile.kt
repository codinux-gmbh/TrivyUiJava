package net.codinux.trivy.report

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

// see https://github.com/google/go-containerregistry/blob/main/pkg/v1/config.go#L29
data class ConfigFile(
    val architecture: String,
    val author: String? = null,
    val container: String? = null,
    val created: Instant? = null,
    @JsonProperty("docker_version")
    val dockerVersion: String? = null,
    val history: List<History> = emptyList(),
    val os: String,
    val rootfs: RootFS,
    val config: Config,
    @JsonProperty("os.version")
    val osVersion: String? = null,
    val variant: String? = null,
    @JsonProperty("os.features")
    val osFeatures: List<String> = emptyList()
)
