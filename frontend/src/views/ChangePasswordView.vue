<script setup lang="ts">
import { computed, reactive, ref } from "vue";

import ProblemPanel from "../components/ProblemPanel.vue";

defineProps<{
  email: string;
}>();

const emit = defineEmits<{
  changePassword: [
    currentPassword: string,
    newPassword: string,
    resolve: () => void,
    reject: (error: unknown) => void,
  ];
  logout: [];
}>();

const form = reactive({
  currentPassword: "",
  newPassword: "",
  confirmPassword: "",
});
const error = ref<unknown>(null);
const submitting = ref(false);

const canSubmit = computed(
  () =>
    form.currentPassword.length > 0 &&
    form.newPassword.length >= 12 &&
    form.newPassword.length <= 256 &&
    form.newPassword === form.confirmPassword,
);

async function submit(): Promise<void> {
  if (!canSubmit.value) return;
  submitting.value = true;
  error.value = null;
  try {
    await new Promise<void>((resolve, reject) => {
      emit("changePassword", form.currentPassword, form.newPassword, resolve, reject);
    });
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
    form.currentPassword = "";
    form.newPassword = "";
    form.confirmPassword = "";
  }
}
</script>

<template>
  <main class="centered-page">
    <section class="password-card" aria-labelledby="password-title">
      <div class="brand-lockup">
        <span class="brand-symbol" aria-hidden="true">DX</span>
        <span>DataX Enterprise Studio</span>
      </div>
      <div>
        <p class="kicker">首次登录保护</p>
        <h1 id="password-title">必须先修改临时密码</h1>
        <p>
          当前账号 <strong>{{ email }}</strong> 使用的是临时密码。完成改密前，后端只允许查看本人、
          刷新会话、改密和退出；这不是前端隐藏按钮实现的限制。
        </p>
      </div>

      <ProblemPanel v-if="error" :error="error" :show-retry="false" />

      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="当前临时密码" required>
          <el-input
            v-model="form.currentPassword"
            type="password"
            autocomplete="current-password"
            maxlength="256"
            show-password
          />
        </el-form-item>
        <el-form-item label="新密码" required>
          <el-input
            v-model="form.newPassword"
            type="password"
            autocomplete="new-password"
            maxlength="256"
            show-password
          />
          <span class="field-help">至少 12 个字符；密码不会写入浏览器持久存储。</span>
        </el-form-item>
        <el-form-item label="确认新密码" required>
          <el-input
            v-model="form.confirmPassword"
            type="password"
            autocomplete="new-password"
            maxlength="256"
            show-password
          />
          <span v-if="form.confirmPassword && form.newPassword !== form.confirmPassword" class="field-error">
            两次输入的新密码不一致
          </span>
        </el-form-item>
        <div class="form-actions form-actions--spread">
          <el-button @click="emit('logout')">退出登录</el-button>
          <el-button type="primary" native-type="submit" :disabled="!canSubmit" :loading="submitting">
            修改密码并继续
          </el-button>
        </div>
      </el-form>
    </section>
  </main>
</template>
