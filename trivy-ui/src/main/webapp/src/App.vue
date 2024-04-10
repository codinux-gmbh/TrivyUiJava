<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
</script>

<template>
  <div class="bg-teal-800 relative text-orange-500 w-full h-14 sm:h-16 leading-[3.5rem] sm:leading-[4rem] z-[997]">
    <nav class="flex items-center justify-between flex-wrap" role="navigation">
      <div class="nav-wrapper ml-5 mr-14">
        <a href="/" class="brand-logo font-semibold text-[1.75rem]">Trivy UI</a>
      </div>

      <div class="block lg:hidden">
        <button class="flex items-center px-3 py-2 border rounded text-teal-200 border-teal-400 hover:text-white hover:border-white">
          <svg class="fill-current h-3 w-3" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><title>Menu</title><path d="M0 3h20v2H0V3zm0 6h20v2H0V9zm0 6h20v2H0v-2z"/></svg>
        </button>
      </div>
      <div class="w-full block flex-grow lg:flex lg:items-center lg:w-auto">
        <div class="text-xl lg:flex-grow">
          <nav class="main-nav">
            <RouterLink to="/">Kubernetes</RouterLink>
            <RouterLink to="/file-system">File system</RouterLink>
            <RouterLink to="/repositories">Repositories</RouterLink>
          </nav>
        </div>
      </div>
    </nav>
  </div>

  <main class="flex-[1_0_auto] bg-zinc-100 lg:pt-4">
    <div class="max-w-[1140px] w-[100%] lg:w-[85%] lg:mx-auto">
      <RouterView />
    </div>
  </main>
</template>

<style scoped>

  nav.main-nav a {
    display: block;

    min-width: 6rem;
    margin-top: 1.5rem;
    margin-right: 1rem;

    text-align: center;
  }

  nav.main-nav a:hover {
    color: white;
  }

  @media (min-width: 1024px) {
    nav.main-nav a {
      display: inline-block;

      margin-top: 0;
    }
  }

</style>
