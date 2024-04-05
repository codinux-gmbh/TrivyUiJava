package net.codinux.trivy.report

data class DetectedLicense(
    /**
     * Severity is the consistent parameter indicating how severe the issue is
     */
    val Severity: String,
    /**
     * Category holds the license category such as "forbidden"
     */
    val Category: LicenseCategory,
    /**
     * PkgName holds a package name of the license.
     * It will be empty if FilePath is filled.
     */
    val PkgName: String,
    /**
     * PkgName holds a file path of the license.
     * It will be empty if PkgName is filled.
     */
    val FilePath: String,
    /**
     * Name holds a detected license name
     */
    val Name: String,
    /**
     * Confidence is level of the match. The confidence level is between 0.0 and 1.0, with 1.0 indicating an
     * exact match and 0.0 indicating a complete mismatch
     */
    val Confidence: Double,
    /**
     * Link is a SPDX link of the license
     */
    val Link: String
)
