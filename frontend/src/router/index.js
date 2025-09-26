import { createRouter, createWebHistory } from "vue-router";
import Login from "../components/Login.vue";
import Home from "../components/Home.vue";
import Page1 from "../components/Page1.vue";
import Page2 from "../components/Page2.vue";

const routes = [
  { path: "/", component: Login },
  { path: "/home", component: Home },
  { path: "/page1", component: Page1},
  { path: "/page2", component: Page2}
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
