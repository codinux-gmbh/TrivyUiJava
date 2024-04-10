<script setup lang="ts">
import {getCurrentInstance, ref} from "vue";

interface ScanReport {
  context?: string,
  scanStart: string,
  countScannedImages: number,
  countCriticalVulnerabilities: number,
  countHighVulnerabilities: number,
  countMediumVulnerabilities: number,
  countLowVulnerabilities: number,
  images: [ImageVulnerabilitiesSummary]
}

interface ImageVulnerabilitiesSummary {
  namespace?: string,
  name: string,
  imageId: string,
  scanner: string,
  countCriticalVulnerabilities: number,
  countHighVulnerabilities: number,
  countMediumVulnerabilities: number,
  countLowVulnerabilities: number
}

const scanReport = ref<ScanReport>()

function fetchScanReport() {
  fetch(getCurrentInstance()?.appContext.config.globalProperties.baseUrl  + "/api/kubernetes/vulnerabilities")
      .then(res => res.json())
      .then(json => scanReport.value = json)
}

fetchScanReport()

</script>

<template>
  <div v-if="scanReport">

    <div class="flex mb-4">
      <div class="flex-1 mr-4 bg-white">
        <div>Context: {{ scanReport?.context }}</div>
        <div>Time: {{ scanReport?.scanStart }}</div>
        <div>Scanned images: {{ scanReport?.countScannedImages }}</div>
      </div>
      <div class="flex-1 bg-white">
        <div>Critical: {{ scanReport?.countCriticalVulnerabilities }}</div>
        <div>High: {{ scanReport?.countHighVulnerabilities }}</div>
        <div>Medium: {{ scanReport?.countMediumVulnerabilities }}</div>
        <div>Low: {{ scanReport?.countLowVulnerabilities }}</div>
      </div>
    </div>

    <div class="table table-auto w-full bg-white text-xs sm:text-sm text-zinc-700 bg-clip-border">
      <div class="table-header-group bg-zinc-200 text-zinc-500 border-b border-zinc-500">
        <div class="table-row">
          <div class="table-cell max-w-[20rem]">Name</div>
          <div class="table-cell max-w-[48rem]">Image</div>
          <div class="table-cell !text-center">Critical</div>
          <div class="table-cell !text-center">High</div>
          <div class="table-cell !text-center">Medium</div>
          <div class="table-cell !text-center !pr-2 lg:!pr-3">Low</div>
        </div>
      </div>
      <div class="table-row-group">
        <div v-for="image in scanReport.images" class="table-row border-b first:border-t border-zinc-200 even:bg-zinc-100/50 lg:hover:bg-zinc-200">
          <div class="table-cell max-w-[20rem] truncate">{{ image.name }}</div>
          <div class="table-cell max-w-[48rem] truncate">{{ image.imageId }}</div>
          <div class="table-cell !text-center">{{ image.countCriticalVulnerabilities }}</div>
          <div class="table-cell !text-center">{{ image.countHighVulnerabilities }}</div>
          <div class="table-cell !text-center">{{ image.countMediumVulnerabilities }}</div>
          <div class="table-cell !text-center">{{ image.countLowVulnerabilities }}</div>
        </div>
      </div>
    </div>

  </div>
</template>

<style scoped>

  .table-cell {
    padding: 0.5rem;
    padding-right: 0;

    line-height: 1.25rem;
    text-align: left;
  }
  @media screen and (min-width: 640px) {
    .table-cell {
      padding: 0.75rem;
      padding-right: 0;

      line-height: 1.5rem;
    }
  }

</style>