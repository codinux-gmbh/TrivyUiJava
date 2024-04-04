plugins {
    kotlin("jvm")
}


kotlin {
    jvmToolchain(17)
}


dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}


tasks.test {
    useJUnitPlatform()
}