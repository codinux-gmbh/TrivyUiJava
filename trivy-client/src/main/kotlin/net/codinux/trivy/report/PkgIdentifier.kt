package net.codinux.trivy.report

data class PkgIdentifier(
//    val PURL: PackageURL,
    val PURL: String? = null,
    val BOMRef: String? = null
)

//// see https://github.com/package-url/packageurl-go/blob/master/packageurl.go#L344
//data class PackageURL(
//    val Type: String,
//    val Namespace: String,
//    val Name: String,
//    val Version: String,
//    val Qualifiers: List<Qualifier>,
//    val Subpath: String
//)
//
//data class Qualifier(
//    val Key: String,
//    val Value: String
//)
