package net.codinux.trivy.report

data class Code(
    // TODO: why can't lines be deserialized?
    val Lines: List<Line> = emptyList()
)
