<script setup lang="ts">

import {getCurrentInstance, ref, watch} from "vue";
import {useRoute} from "vue-router";

interface ReportResponse {
  error?: string,
  report?: Report
}

interface Report {
  results: [Result]
}

interface Result {
  vulnerabilities: [DetectedVulnerability]
}

interface DetectedVulnerability {
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

interface CVSS {
  v2Vector?: string,
  v3Vector?: string,
  v2Score?: number,
  v3Score?: number
}

const reportResponse = ref<ReportResponse>()
const route = useRoute()

function fetchScanReport() {
  const imageId = encodeURIComponent(useRoute().params.imageId as string)

  fetch(getCurrentInstance()?.appContext.config.globalProperties.baseUrl  + `/api/image/${imageId}/vulnerabilities`)
      .then(res => res.json())
      .then(json => reportResponse.value = json)
}

// see https://router.vuejs.org/guide/essentials/dynamic-matching.html#Reacting-to-Params-Changes
watch(() => route.params.imageId, (newId, oldId) => {
  fetchScanReport()
})

function getVulnerabilities(report: Report): DetectedVulnerability[] {
  return report.results.flatMap(result => result.vulnerabilities)
}

function getVulnerabilityUrl(vulnerability: DetectedVulnerability): string | null {
  if (vulnerability.primaryUrl) {
    return vulnerability.primaryUrl
  }

  if (vulnerability.references) {
    return vulnerability.references[0]
  }

  return null
}

function getScore(vulnerability: DetectedVulnerability): number | null {
  const cvsses = vulnerability.cvss

  if (cvsses) {
    const scores = [...Object.values(cvsses)].map(cvss => cvss.v3Score ?? cvss.v2Score).filter(cvss => cvss != undefined) as number[]

    if (scores.length) {
      return Math.max(...scores)
    }
  }

  return null
}

fetchScanReport()

</script>

<template>

  <div v-if="reportResponse?.report">

    <div class="table table-auto w-full bg-white text-xs sm:text-sm text-zinc-700 bg-clip-border">
      <div class="table-header-group bg-zinc-200 text-zinc-500 border-b border-zinc-500">
        <div class="table-row">
          <div class="table-cell">Vulnerability ID</div>
          <div class="table-cell">Severity</div>
          <div class="table-cell">Score</div>
          <div class="table-cell max-w-[20rem]">Title</div>
          <div class="table-cell">Resource</div>
          <div class="table-cell">Status</div>
          <div class="table-cell">Installed Version</div>
          <div class="table-cell">Fixed Version</div>
          <div class="table-cell">Link</div>
        </div>
      </div>
      <div class="table-row-group">
        <div v-for="vulnerability in getVulnerabilities(reportResponse.report)" class="table-row border-b first:border-t border-zinc-200 even:bg-zinc-100/50 lg:hover:bg-zinc-200">
          <div class="table-cell">{{ vulnerability.vulnerabilityID }}</div>
          <div class="table-cell">{{ vulnerability.severity }}</div>
          <div class="table-cell">{{ getScore(vulnerability) }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ vulnerability.title }}</div>
          <div class="table-cell">{{ vulnerability.pkgName }}</div>
          <div class="table-cell">{{ vulnerability.status }}</div>
          <div class="table-cell">{{ vulnerability.installedVersion }}</div>
          <div class="table-cell">{{ vulnerability.fixedVersion }}</div>
          <div class="table-cell"><a v-if="getVulnerabilityUrl(vulnerability)" v-bind:href="getVulnerabilityUrl(vulnerability) as string">Link</a></div>
        </div>
      </div>
    </div>

  </div>

</template>

<style scoped>

</style>