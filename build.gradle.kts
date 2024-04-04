buildscript {
    val kotlinVersion: String by extra

    repositories {
        mavenCentral()
    }

    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
    }
}


allprojects {
    group = "net.codinux.trivy"
    version = "1.0.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }


    apply(plugin = "org.jetbrains.kotlin.jvm")
}