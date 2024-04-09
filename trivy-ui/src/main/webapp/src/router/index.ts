import { createRouter, createWebHistory } from 'vue-router'
import KubernetesView from "@/views/KubernetesView.vue";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: KubernetesView
    },
    {
      path: '/file-system',
      name: 'file-system',
      // route level code-splitting
      // this generates a separate chunk (About.[hash].js) for this route
      // which is lazy-loaded when the route is visited.
      component: () => import('../views/FileSystemView.vue')
    },
    {
      path: '/repositories',
      name: 'repositories',
      component: () => import('../views/RepositoriesView.vue')
    }
  ]
})

export default router
