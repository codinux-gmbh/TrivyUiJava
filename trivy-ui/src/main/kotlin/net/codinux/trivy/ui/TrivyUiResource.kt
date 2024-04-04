package net.codinux.trivy.ui

import io.quarkus.qute.Template
import io.quarkus.qute.TemplateInstance
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path

@Path("/")
class TrivyUiResource(
    private val index: Template
) {

    @GET
    fun index(): TemplateInstance =
        index.instance()

}