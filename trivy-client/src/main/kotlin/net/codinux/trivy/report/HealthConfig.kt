package net.codinux.trivy.report

import java.time.Duration

data class HealthConfig(
    /**
     * Test is the test to perform to check that the container is healthy.
     * An empty slice means to inherit the default.
     * The options are:
     * {} : inherit healthcheck
     * {"NONE"} : disable healthcheck
     * {"CMD", args...} : exec arguments directly
     * {"CMD-SHELL", command} : run command with system's default shell
     */
    val Test: List<String> = emptyList(),
    val Interval: DurationNanoseconds? = null,
    val Timeout: DurationNanoseconds? = null,
    val StartPeriod: DurationNanoseconds? = null,
    val Retries: Int? = null
)
