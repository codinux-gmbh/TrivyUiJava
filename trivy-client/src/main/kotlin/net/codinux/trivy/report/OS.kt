package net.codinux.trivy.report

data class OS(
    val Family: OSType,
    val Name: String,
    val Eosl: Boolean? = null,
    /**
     * This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
     */
    val Extended: Boolean? = null
)
