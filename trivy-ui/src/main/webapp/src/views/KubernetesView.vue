<script setup lang="ts">
import {RouterLink, RouterView} from "vue-router";
</script>

<template>
  <div class="flex max-md:flex-col">
    <div class="sidebar-nav p-4 bg-white">
      <RouterLink to="/kubernetes/images">Images</RouterLink>
      <RouterLink to="/kubernetes/secrets">Secrets</RouterLink>
      <RouterLink to="/kubernetes/misconfiguration">Misconfiguration</RouterLink>
      <RouterLink to="/kubernetes/rbac">RBAC</RouterLink>
    </div>

    <div class="kubernetes-child-view lg:flex-[1_0_auto]">
      <RouterView />
    </div>
  </div>
</template>

<style scoped>
  .sidebar-nav a {
    display: inline-block;
    margin-right: 0.5rem;
  }

  @media (min-width: 1024px) {
    .sidebar-nav {
      display: block;

      margin-right: 1rem;
    }

    .sidebar-nav a {
      display: block;

      line-height: 2;
    }
  }

</style>