<script setup lang="ts">

import {getCurrentInstance, ref} from "vue";

interface MisconfigurationScanReport {
  context?: string,
  successes: number,
  failures: number,
  exceptions: number,
  resourceMisconfigurations: [ResourceMisconfigurations]
}

interface ResourceMisconfigurations {
  namespace?: string,
  kind: string,
  name: string,
  successes: number,
  failures: number,
  exceptions: number
}

const scanReport = ref<MisconfigurationScanReport>()

function fetchScanReport() {
  fetch(getCurrentInstance()?.appContext.config.globalProperties.baseUrl  + "/api/kubernetes/rbac")
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
        <div>Scanned images: {{ scanReport.resourceMisconfigurations.length }}</div>
      </div>
      <div class="flex-1 bg-white">
        <div>Successes: {{ scanReport.successes }}</div>
        <div>Failures: {{ scanReport.failures }}</div>
        <div>Exceptions: {{ scanReport.exceptions }}</div>
      </div>
    </div>

    <div class="table table-auto w-full bg-white text-xs sm:text-sm text-zinc-700 bg-clip-border">
      <div class="table-header-group bg-zinc-200 text-zinc-500 border-b border-zinc-500">
        <div class="table-row">
          <div class="table-cell max-w-[11rem]">Namespace</div>
          <div class="table-cell max-w-[20rem]">Kind</div>
          <div class="table-cell max-w-[20rem]">Name</div>
          <div class="table-cell !text-center">Successes</div>
          <div class="table-cell !text-center">Failures</div>
          <div class="table-cell !text-center !pr-2 lg:!pr-3">Exceptions</div>
        </div>
      </div>
      <div class="table-row-group">
        <div v-for="resource in scanReport.resourceMisconfigurations" class="table-row border-b first:border-t border-zinc-200 even:bg-zinc-100/50 lg:hover:bg-zinc-200">
          <div class="table-cell max-w-[11rem] truncate">{{ resource.namespace }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ resource.kind }}</div>
          <div class="table-cell max-w-[20rem] truncate">{{ resource.name }}</div>
          <div class="table-cell !text-center">{{ resource.successes }}</div>
          <div class="table-cell !text-center">{{ resource.failures }}</div>
          <div class="table-cell !text-center">{{ resource.exceptions }}</div>
        </div>
      </div>
    </div>

  </div>
</template>