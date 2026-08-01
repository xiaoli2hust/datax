<script setup lang="ts">
import { defineAsyncComponent, onBeforeUnmount, onMounted } from "vue";

import { useAuth } from "./state/auth";
import { useHealth } from "./state/health";
import ChangePasswordView from "./views/ChangePasswordView.vue";
import LoginView from "./views/LoginView.vue";

const WorkbenchView = defineAsyncComponent(() => import("./views/WorkbenchView.vue"));

const auth = useAuth();
const health = useHealth();
let healthTimer: number | undefined;

async function handleLogin(
  email: string,
  password: string,
  resolve: () => void,
  reject: (error: unknown) => void,
): Promise<void> {
  try {
    await auth.login(email, password);
    resolve();
  } catch (error) {
    reject(error);
  }
}

async function handleForcedPasswordChange(
  currentPassword: string,
  newPassword: string,
  resolve: () => void,
  reject: (error: unknown) => void,
): Promise<void> {
  try {
    await auth.changePassword(currentPassword, newPassword);
    resolve();
  } catch (error) {
    reject(error);
  }
}

onMounted(() => {
  void auth.initialize();
  void health.refresh();
  healthTimer = window.setInterval(() => void health.refresh(), 10_000);
});

onBeforeUnmount(() => {
  if (healthTimer !== undefined) window.clearInterval(healthTimer);
  health.stop();
});
</script>

<template>
  <main v-if="auth.state.initializing" class="boot-screen" aria-live="polite">
    <div class="brand-lockup">
      <span class="brand-symbol" aria-hidden="true">DX</span>
      <span>DataX Enterprise Studio</span>
    </div>
    <el-skeleton :rows="4" animated />
    <p>正在恢复本机安全会话并读取真实服务状态…</p>
  </main>

  <LoginView
    v-else-if="!auth.authenticated.value"
    :health="health.health.value"
    :health-loading="health.loading.value"
    :health-error="health.error.value"
    @login="handleLogin"
    @refresh-health="health.refresh"
  />

  <ChangePasswordView
    v-else-if="auth.mustChangePassword.value"
    :email="auth.state.user?.email ?? ''"
    @change-password="handleForcedPasswordChange"
    @logout="auth.logout"
  />

  <WorkbenchView
    v-else
    :health="health.health.value"
    :health-loading="health.loading.value"
    :health-error="health.error.value"
    @refresh-health="health.refresh"
  />
</template>
