
<script setup lang="ts">

import {Input} from "postcss";
import {getCurrentInstance, ref} from "vue";
import {Dto} from "@/dto/ReportResponse";
import {useRouter} from "vue-router";

const response = ref<Dto.ReportResponse>()
const baseUrl = getCurrentInstance()?.appContext.config.globalProperties.baseUrl
const router = useRouter()

function scanImage() {
  const input = document.getElementById("imageToScan") as HTMLInputElement
  const imageToScan = encodeURIComponent(input.value)

  fetch(baseUrl  + `/api/image/${imageToScan}/vulnerabilities`)
      .then(res => res.json())
      .then(json => response.value = json)
}

function showImageScanReport(report: Dto.Report) {
  const imageId = encodeURIComponent(report.artifactName)
  router.push(`/images/${imageId}/vulnerabilities`) // TODO: actually redundant as `/images/${imageId}/vulnerabilities` fetches Report again which we already have here. But as it's cached in backend it's not that big issue
}

function getCountSeverities(report: Dto.Report, severity: string): number {
  return Dto.getVulnerabilities(report)
      .filter(vulnerability => vulnerability.severity === severity)
      .length
}

</script>

<template>
  <div>
    <div class="flex items-center w-full h-12">
      <label for="imageToScan" class="flex select-none pointer-events-none">
        Image to scan
      </label>
      <input id="imageToScan" type="text" placeholder="Enter image to scan" class="flex-1 h-full mx-2 px-3 rounded-[7px]" @keydown.enter.prevent="scanImage" />

      <button type="button" class="w-[10rem] h-full py-2 px-4 rounded bg-blue-500 hover:bg-blue-700 text-white font-bold focus:outline-none focus:shadow-outline" @click="scanImage">Scan</button>
    </div>

    <div v-if="response" class="min-h-[11rem] mt-4 p-4 bg-white">
      <div v-if="response.error" class="whitespace-pre-wrap">
        Error: {{ response.error }}
      </div>

      <div v-if="response.report" class="cursor-pointer" @click="showImageScanReport(response.report)">
        <div>ImageId: {{ response.report.artifactName }}</div>
        <div>Time: {{ response.report.createdAt }}</div>
        <div>Critical: {{ getCountSeverities(response.report, "CRITICAL") }}</div>
        <div>High: {{ getCountSeverities(response.report, "HIGH") }}</div>
        <div>Medium: {{ getCountSeverities(response.report, "MEDIUM") }}</div>
        <div>Low: {{ getCountSeverities(response.report, "LOW") }}</div>
      </div>
    </div>
  </div>
</template>