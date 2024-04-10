
export module Dto {

    export interface ReportResponse {
        error?: string,
        report?: Report
    }

    export interface Report {
        createdAt?: string,
        artifactName: string,
        results: [Result]
    }

    export interface Result {
        vulnerabilities: [DetectedVulnerability]
    }

    export interface DetectedVulnerability {
        vulnerabilityID: string,
        pkgName: string,
        severity: string,
        title: string,
        description?: string,
        status?: string,
        installedVersion: string,
        fixedVersion?: string,
        primaryUrl?: string,
        references: [string],
        cvss: Map<string, CVSS>
    }

    export interface CVSS {
        v2Vector?: string,
        v3Vector?: string,
        v2Score?: number,
        v3Score?: number
    }


    export function getVulnerabilities(report: Report): DetectedVulnerability[] {
        return report.results.flatMap(result => result.vulnerabilities)
    }

    export function getVulnerabilityUrl(vulnerability: Dto.DetectedVulnerability): string | null {
        if (vulnerability.primaryUrl) {
            return vulnerability.primaryUrl
        }

        if (vulnerability.references) {
            return vulnerability.references[0]
        }

        return null
    }

    export function getScore(vulnerability: Dto.DetectedVulnerability): number | null {
        const cvsses = vulnerability.cvss

        if (cvsses) {
            const scores = [...Object.values(cvsses)].map(cvss => cvss.v3Score ?? cvss.v2Score).filter(cvss => cvss != undefined) as number[]

            if (scores.length) {
                return Math.max(...scores)
            }
        }

        return null
    }

}