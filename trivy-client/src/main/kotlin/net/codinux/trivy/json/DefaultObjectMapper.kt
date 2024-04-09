package net.codinux.trivy.json

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule

object DefaultObjectMapper {

    val mapper = ObjectMapper().apply {
        this.registerModules(
            JavaTimeModule(),
            KotlinModule.Builder().build()
        )

        this.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
    }

}