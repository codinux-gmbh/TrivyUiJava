import com.github.gradle.node.npm.task.NpxTask

plugins {
    kotlin("jvm")
    kotlin("plugin.allopen")

    id("io.quarkus")

    id("com.github.node-gradle.node") version "7.0.2"
}


kotlin {
    jvmToolchain(17)
}


val quarkusVersion: String by project

val kmpLogVersion: String by project
val lokiLogAppenderVersion: String by project

dependencies {
    implementation(enforcedPlatform("io.quarkus.platform:quarkus-bom:$quarkusVersion"))

    implementation("io.quarkus:quarkus-kotlin")
    implementation("io.quarkus:quarkus-resteasy-reactive")
    implementation("io.quarkus:quarkus-resteasy-reactive-jackson")
    implementation("io.quarkus:quarkus-resteasy-reactive-qute")

    implementation("io.quarkus:quarkus-smallrye-health")
    implementation("io.quarkus:quarkus-smallrye-openapi")
    implementation("io.quarkus:quarkus-micrometer-registry-prometheus")

    implementation(project(":trivy-client"))

    implementation("net.codinux.log:kmp-log:$kmpLogVersion")
    implementation("net.codinux.log:quarkus-loki-log-appender:$lokiLogAppenderVersion")
    implementation("net.codinux.log.kubernetes:codinux-kubernetes-info-retriever:$lokiLogAppenderVersion")


    testImplementation("io.quarkus:quarkus-junit5")
    testImplementation("io.rest-assured:rest-assured")
}


allOpen {
    annotation("jakarta.ws.rs.Path")
    annotation("jakarta.enterprise.context.ApplicationScoped")
    annotation("jakarta.persistence.Entity")
    annotation("io.quarkus.test.junit.QuarkusTest")
}


val buildFrontend = tasks.register<Exec>("buildFrontend") {
    group = "frontend"
    description = "Runs steps to build frontend like run PostCSS to create TailwindCSS file etc."

    commandLine("npm", "run", "build")
}

tasks.named("processResources") {
    dependsOn(buildFrontend)
}

val buildWebAppTask = tasks.register<NpxTask>("buildWebApp") {
    dependsOn("yarnInstall")
    group = "frontend"
    description = "Transpiles Vue.js components to standard JavaScript and CSS files and copies them to src/resources/META-INF/resources"

    workingDir.set(File("$projectDir/src/main/webapp"))

    command.set("yarn")
    args.addAll("run", "build")
}

tasks.named("quarkusBuild") {
    dependsOn(buildWebAppTask)
}

val watchWebAppChangesTask = tasks.register("watchWebAppChanges") {
    dependsOn("yarnInstall")
    group = "frontend"
    description = "On each change to Vue.js files transpiles components to standard JavaScript and CSS files and copies them to src/resources/META-INF/resources"

    doFirst {
        // asynchronously start file watch that transpiles Vue.js files and copies them to src/resources/META-INF/resources
        this.extra["process"] = ProcessBuilder()
            .directory(File("$projectDir/src/main/webapp"))
            .command("yarn", "watch")
            .start()
    }
}

val stopWatchingVueJsChangesTask = tasks.register("stopWatchingVueJsChanges") {
    group = "frontend"
    description = "Stops watching changes to Vue.js files"

    doFirst {
        // stop async file watch process again
        (watchWebAppChangesTask.get().extra["process"] as? Process)?.destroy()
    }
}

tasks.named("quarkusDev") {
    dependsOn(watchWebAppChangesTask)

    finalizedBy(stopWatchingVueJsChangesTask)
}


tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions.javaParameters = true
}

tasks.withType<Test> {
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}
