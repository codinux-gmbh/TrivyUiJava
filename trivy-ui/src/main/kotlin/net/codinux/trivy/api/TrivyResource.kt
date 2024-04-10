package net.codinux.trivy.api

import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import net.codinux.trivy.TrivyService
import net.codinux.trivy.api.dto.ScanReport
import net.codinux.trivy.api.mapper.TrivyDtoMapper
import org.jboss.resteasy.reactive.RestQuery
import java.time.Instant

@Path("/api")
class TrivyResource(
    private val service: TrivyService,
    private val mapper: TrivyDtoMapper
) {

    @GET
    @Path("/kubernetes/vulnerabilities")
    fun getAllImageVulnerabilitiesOfKubernetesCluster(@RestQuery("context") context: String? = null): ScanReport {
        val start = Instant.now()
        val vulnerabilities = service.getAllImageVulnerabilitiesOfKubernetesCluster(context)

        return mapper.mapToScanReport(context, start, vulnerabilities)
    }

}