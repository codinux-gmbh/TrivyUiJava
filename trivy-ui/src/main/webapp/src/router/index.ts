import { createRouter, createWebHistory } from 'vue-router'
import KubernetesView from "@/views/KubernetesView.vue";
import KubernetesImagesView from '@/views/kubernetes/KubernetesImagesView.vue';
import KubernetesSecretsView from "@/views/kubernetes/KubernetesSecretsView.vue";
import KubernetesMisconfigurationView from "@/views/kubernetes/KubernetesMisconfigurationView.vue";
import KubernetesRbacView from "@/views/kubernetes/KubernetesRbacView.vue";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: "/",
      redirect: "/kubernetes",
    },
    {
      path: "/kubernetes",
      name: "home",
      component: KubernetesView,
      children: [
        { path: "images", component: KubernetesImagesView },
        { path: "secrets", component: KubernetesSecretsView },
        { path: "misconfiguration", component: KubernetesMisconfigurationView },
        { path: "rbac", component: KubernetesRbacView },
      ]
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
