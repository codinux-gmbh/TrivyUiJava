plugins {
    kotlin("jvm")
}


kotlin {
    jvmToolchain(17)
}


val kmpLogVersion: String by project

val assertKVersion: String by project

dependencies {
    implementation("net.codinux.log:kmp-log:$kmpLogVersion")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("com.willowtreeapps.assertk:assertk:$assertKVersion")
}


tasks.test {
    useJUnitPlatform()
}