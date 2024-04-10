import './assets/css/main.css'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

const app = createApp(App)
    .use(router)

const isDevMode = import.meta.env.DEV
app.config.globalProperties.baseUrl = isDevMode ? "http://localhost:8092" : window.location.origin

app.mount('#app')
