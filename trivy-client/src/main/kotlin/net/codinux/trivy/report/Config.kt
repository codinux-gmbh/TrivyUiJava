package net.codinux.trivy.report

data class Config(
    val AttachStderr: Boolean? = null,
    val AttachStdin: Boolean? = null,
    val AttachStdout: Boolean? = null,
    val Cmd: List<String> = emptyList(),
    val Healthcheck: HealthConfig? = null,
    val Domainname: String? = null,
    val Entrypoint: List<String> = emptyList(),
    val Env: List<String> = emptyList(),
    val Hostname: String? = null,
    val Image: String? = null,
    val Labels: Map<String, String> = emptyMap(),
    val OnBuild: List<String> = emptyList(),
    val OpenStdin: Boolean? = null,
    val StdinOnce: Boolean? = null,
    val Tty: Boolean? = null,
    val User: String? = null,
    val Volumes: Map<String, Any> = emptyMap(),
    val WorkingDir: String? = null,
    val ExposedPorts: Map<String, Any> = emptyMap(),
    val ArgsEscaped: Boolean? = null,
    val NetworkDisabled: Boolean? = null,
    val MacAddress: String? = null,
    val StopSignal: String? = null,
    val Shell: List<String> = emptyList()
)
