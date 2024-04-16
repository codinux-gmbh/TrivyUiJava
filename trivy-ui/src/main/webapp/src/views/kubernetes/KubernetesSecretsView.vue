<script setup lang="ts">

import {getCurrentInstance, ref} from "vue";

interface SecretsScanReport {
  context?: string,
  // scanStart: string,
  countScannedResources: number,
  countCriticalSeverities: number,
  countHighSeverities: number,
  countMediumSeverities: number,
  countLowSeverities: number,
  resources: [ResourceSecretsScanSummary]
}

interface ResourceSecretsScanSummary {
  namespace?: string,
  kind: string,
  name: string,
  imageId?: string,
  imageTags: [string],
  scanner: string,
  countCriticalSeverities: number,
  countHighSeverities: number,
  countMediumSeverities: number,
  countLowSeverities: number
}

const scanReport = ref<SecretsScanReport>()

function fetchScanReport() {
  fetch(getCurrentInstance()?.appContext.config.globalProperties.baseUrl  + "/api/kubernetes/secrets")
      .then(res => res.json())
      .then(json => scanReport.value = json)
}

fetchScanReport()

</script>

<template>
  <div v-if="scanReport">

    <div class="flex mb-4">
      <div class="flex-1 mr-4 bg-white">
        <div>Context: {{ scanReport.context }}</div>
<!--        <div>Time: {{ scanReport.scanStart }}</div>-->
        <div>Scanned images: {{ scanReport.countScannedResources }}</div>
      </div>
      <div class="flex-1 bg-white">
        <div>Critical: {{ scanReport.countCriticalSeverities }}</div>
        <div>High: {{ scanReport.countHighSeverities }}</div>
        <div>Medium: {{ scanReport.countMediumSeverities }}</div>
        <div>Low: {{ scanReport.countLowSeverities }}</div>
      </div>
    </div>

    <div class="table table-auto w-full bg-white text-xs sm:text-sm text-zinc-700 bg-clip-border">
      <div class="table-header-group bg-zinc-200 text-zinc-500 border-b border-zinc-500">
        <div class="table-row">
          <div class="table-cell max-w-[11rem]">Namespace</div>
          <div class="table-cell max-w-[20rem]">Kind</div>
          <div class="table-cell max-w-[20rem]">Name</div>
          <div class="table-cell max-w-[30rem]">Image</div>
          <div class="table-cell max-w-[20rem]">Tags</div>
          <div class="table-cell !text-center">Critical</div>
          <div class="table-cell !text-center">High</div>
          <div class="table-cell !text-center">Medium</div>
          <div class="table-cell !text-center !pr-2 lg:!pr-3">Low</div>
        </div>
      </div>
      <div class="table-row-group">
        <div v-for="resource in scanReport.resources" class="table-row border-b first:border-t border-zinc-200 even:bg-zinc-100/50 lg:hover:bg-zinc-200">
          <div class="table-cell max-w-[11rem] truncate">{{ resource.namespace }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ resource.kind }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ resource.name }}</div>
          <div class="table-cell max-w-[30rem] truncate">{{ resource.imageId }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ resource.imageTags.join(", ") }}</div>
          <div class="table-cell !text-center">{{ resource.countCriticalSeverities }}</div>
          <div class="table-cell !text-center">{{ resource.countHighSeverities }}</div>
          <div class="table-cell !text-center">{{ resource.countMediumSeverities }}</div>
          <div class="table-cell !text-center">{{ resource.countLowSeverities }}</div>
        </div>
      </div>
    </div>

  </div>
</template>