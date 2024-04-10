package net.codinux.trivy.domain.config

import io.quarkus.runtime.Startup
import jakarta.enterprise.inject.Produces
import jakarta.inject.Singleton
import net.codinux.trivy.TrivyService

@Singleton
@Startup
class QuarkusConfig {

    @Produces
    fun trivyService(): TrivyService = TrivyService()

}