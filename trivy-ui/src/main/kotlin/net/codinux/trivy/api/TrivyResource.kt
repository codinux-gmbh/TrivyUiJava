package net.codinux.trivy.api

import io.quarkus.runtime.Startup
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import net.codinux.trivy.TrivyService
import net.codinux.trivy.api.dto.ReportResponse
import net.codinux.trivy.api.dto.VulnerabilitiesScanReport
import net.codinux.trivy.api.mapper.TrivyDtoMapper
import org.jboss.resteasy.reactive.RestPath
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
    fun getKubernetesClusterVulnerabilities(@RestQuery("context") context: String? = null): VulnerabilitiesScanReport {
        val start = Instant.now()
        val (report, error) = service.getKubernetesClusterVulnerabilities(context)

        return mapper.mapToScanReport(context, start, report, error)
    }

    @GET
    @Path("/kubernetes/secrets")
    fun getKubernetesClusterExposedSecrets(@RestQuery("context") context: String? = null): VulnerabilitiesScanReport {
        val start = Instant.now()
        val (report, error) = service.getKubernetesClusterExposedSecrets(context)

        return mapper.mapToScanReport(context, start, report, error)
    }

    @GET
    @Path("/kubernetes/rbac")
    fun getKubernetesClusterRbacMisconfiguration(@RestQuery("context") context: String? = null): VulnerabilitiesScanReport {
        val start = Instant.now()
        val (report, error) = service.getKubernetesClusterRbacMisconfiguration(context)

        return mapper.mapToScanReport(context, start, report, error)
    }

    @GET
    @Path("/image/{imageId}/vulnerabilities")
    fun getImageVulnerabilities(@RestPath("imageId") imageId: String): ReportResponse {
        val (report, error) = service.getVulnerabilitiesOfImage(imageId)

        return ReportResponse(error, report)
    }

}