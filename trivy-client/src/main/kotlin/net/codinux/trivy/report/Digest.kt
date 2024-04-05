package net.codinux.trivy.report

// Digest allows simple protection of hex formatted digest strings, prefixed by their algorithm.
//
// The following is an example of the contents of Digest types:
//
//	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
typealias Digest = String

// supported digest types
//const (
//    SHA1   Algorithm = "sha1"   // sha1 with hex encoding (lower case only)
//    SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
//    MD5    Algorithm = "md5"    // md5 with hex encoding (lower case only)
//)