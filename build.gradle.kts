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

    ext["sourceCodeRepositoryBaseUrl"] = "github.com/codinux/TrivyUI"
    ext["projectDescription"] = "UI and API that makes the functionality of the security scanner Trivy available for JVM"

    repositories {
        mavenCentral()
    }


    apply(plugin = "org.jetbrains.kotlin.jvm")
}