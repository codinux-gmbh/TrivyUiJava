plugins {
    kotlin("jvm")
}


java {
    withSourcesJar()

    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}



val fabric8KubernetesClientVersion: String by project
val jacksonVersion: String by project
val kmpLogVersion: String by project

val assertKVersion: String by project
val logbackVersion: String by project

dependencies {
    implementation("io.fabric8:kubernetes-client:$fabric8KubernetesClientVersion")
    implementation("io.fabric8:kubernetes-httpclient-jdk:$fabric8KubernetesClientVersion")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77") // required for Fabric8 Kubernetes Client

    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")

    implementation("net.codinux.log:kmp-log:$kmpLogVersion")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("com.willowtreeapps.assertk:assertk:$assertKVersion")
    testImplementation("ch.qos.logback:logback-classic:$logbackVersion")
}


tasks.test {
    useJUnitPlatform()
}