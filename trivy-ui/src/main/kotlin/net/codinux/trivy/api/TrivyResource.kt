package net.codinux.trivy.api

import io.quarkus.runtime.Startup
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import net.codinux.trivy.TrivyService
import net.codinux.trivy.api.dto.ScanReport
import net.codinux.trivy.api.mapper.TrivyDtoMapper
import org.jboss.resteasy.reactive.RestQuery
import java.time.Instant

@Startup // so that TrivyService get created and therefore clusters get scanned at start-up, and not on first call to API
@Path("/api")
class TrivyResource(
    private val service: TrivyService,
    private val mapper: TrivyDtoMapper
) {

    @GET
    @Path("/kubernetes/vulnerabilities")
    fun getAllImageVulnerabilitiesOfKubernetesCluster(@RestQuery("context") context: String? = null): ScanReport {
        val start = Instant.now()
        val scanReports = service.getAllImageVulnerabilitiesOfKubernetesCluster(context)

        return mapper.mapToScanReport(context, start, scanReports)
    }

}