<script setup lang="ts">

import {getCurrentInstance, ref, watch} from "vue";
import {useRoute} from "vue-router";
import {Dto} from "@/dto/ReportResponse";

const reportResponse = ref<Dto.ReportResponse>()
const route = useRoute()

function fetchScanReport() {
  const imageId = encodeURIComponent(route.params.imageId as string)

  fetch(getCurrentInstance()?.appContext.config.globalProperties.baseUrl  + `/api/image/${imageId}/vulnerabilities`)
      .then(res => res.json())
      .then(json => reportResponse.value = json)
}

// see https://router.vuejs.org/guide/essentials/dynamic-matching.html#Reacting-to-Params-Changes
watch(() => route.params.imageId, (newId, oldId) => {
  fetchScanReport()
})

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
        <div v-for="vulnerability in Dto.getVulnerabilities(reportResponse.report)" class="table-row border-b first:border-t border-zinc-200 even:bg-zinc-100/50 lg:hover:bg-zinc-200">
          <div class="table-cell">{{ vulnerability.vulnerabilityID }}</div>
          <div class="table-cell">{{ vulnerability.severity }}</div>
          <div class="table-cell">{{ Dto.getScore(vulnerability) }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ vulnerability.title }}</div>
          <div class="table-cell">{{ vulnerability.pkgName }}</div>
          <div class="table-cell">{{ vulnerability.status }}</div>
          <div class="table-cell">{{ vulnerability.installedVersion }}</div>
          <div class="table-cell">{{ vulnerability.fixedVersion }}</div>
          <div class="table-cell"><a v-if="Dto.getVulnerabilityUrl(vulnerability)" v-bind:href="Dto.getVulnerabilityUrl(vulnerability) as string">Link</a></div>
        </div>
      </div>
    </div>

  </div>

</template>

<style scoped>

</style>