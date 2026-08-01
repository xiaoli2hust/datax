<script setup lang="ts">
import { reactive, ref } from "vue";

import { isApiError } from "../api/client";
import HealthPanel from "../components/HealthPanel.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import type { HealthResponse } from "../types";

defineProps<{
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: string | null;
}>();

const emit = defineEmits<{
  login: [
    email: string,
    password: string,
    resolve: () => void,
    reject: (error: unknown) => void,
  ];
  refreshHealth: [];
}>();

const form = reactive({
  email: "",
  password: "",
});
const submitting = ref(false);
const error = ref<unknown>(null);

async function submit(): Promise<void> {
  if (!form.email.trim() || !form.password) return;
  submitting.value = true;
  error.value = null;
  try {
    await emitAsyncLogin();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
    form.password = "";
  }
}

function emitAsyncLogin(): Promise<void> {
  return new Promise((resolve, reject) => {
    emit("login", form.email.trim(), form.password, resolve, reject);
  });
}

function retry(): void {
  if (isApiError(error.value) && error.value.problem.retryable) void submit();
  else error.value = null;
}
</script>

<template>
  <main class="login-page">
    <section class="login-brand" aria-labelledby="login-brand-title">
      <div class="brand-lockup">
        <span class="brand-symbol" aria-hidden="true">DX</span>
        <span>DataX Enterprise Studio</span>
      </div>
      <div>
        <p class="eyebrow">WINDOWS 本地工作站</p>
        <h1 id="login-brand-title">一次性复制，<br />每一步都有事实依据。</h1>
        <p class="login-lead">
          从任务版本、人工确认、固定 DataX Runtime 到独立数据核验，都保留在本机审计链中。
          服务仅通过 <code>127.0.0.1:17860</code> 访问。
        </p>
      </div>
      <div class="boundary-note">
        <strong>本机单节点 · 非 HA</strong>
        <span>电脑睡眠、关机或 Docker Desktop 停止时服务不可用；恢复后先进行执行对账。</span>
      </div>
    </section>

    <section class="login-card" aria-labelledby="login-title">
      <div>
        <p class="kicker">安全登录</p>
        <h2 id="login-title">进入本机控制台</h2>
        <p class="muted">使用 Launcher 首次引导创建的账号，或 Admin 分配的本地账号。</p>
      </div>

      <ProblemPanel v-if="error" :error="error" @retry="retry" />

      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="登录邮箱" required>
          <el-input
            v-model="form.email"
            autocomplete="username"
            inputmode="email"
            maxlength="254"
            placeholder="name@example.com"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-form-item label="密码" required>
          <el-input
            v-model="form.password"
            type="password"
            autocomplete="current-password"
            maxlength="256"
            show-password
            placeholder="输入密码"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button
          class="full-width"
          native-type="submit"
          type="primary"
          size="large"
          :loading="submitting"
          :disabled="!form.email.trim() || !form.password"
        >
          {{ submitting ? "登录中…" : "登录" }}
        </el-button>
      </el-form>

      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="无法访问时"
        description="请从 Windows 桌面快捷方式打开 Launcher，并确认 Docker Desktop 正在运行。无需填写服务器地址。"
      />

      <HealthPanel
        compact
        :health="health"
        :loading="healthLoading"
        :error="healthError"
        @refresh="emit('refreshHealth')"
      />
    </section>
  </main>
</template>
