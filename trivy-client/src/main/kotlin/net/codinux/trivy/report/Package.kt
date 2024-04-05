package net.codinux.trivy.report

data class Package(
    val ID: String? = null,
    val Name: String? = null,
    val Identifier: PkgIdentifier? = null,
    val Version: String? = null,
    val Release: String? = null,
    val Epoch: Int? = null,
    val Arch: String? = null,
    val Dev: Boolean? = null,
    val SrcName: String? = null,
    val SrcVersion: String? = null,
    val SrcRelease: String? = null,
    val SrcEpoch: Int? = null,
    val Licenses: List<String> = emptyList(),
    val Maintainer: String? = null,
    val Modularitylabel: String? = null,
    val BuildInfo: BuildInfo? = null,
    val Indirect: Boolean? = null,
    val DependsOn: List<String> = emptyList(),
    val Layer: Layer? = null,
    val FilePath: String? = null,
    val Digest: Digest? = null,
    val Locations: List<Location> = emptyList(),
    val InstalledFiles: List<String> = emptyList()
)
