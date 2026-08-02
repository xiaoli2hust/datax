<script setup lang="ts">
import { computed } from "vue";

import {
  datasourceOperationManualRetryGuidance,
  isApiError,
  requiresManualDatasourceOperationRetry,
} from "../api/client";

const props = defineProps<{
  error: unknown;
  title?: string;
  showRetry?: boolean;
}>();

const emit = defineEmits<{
  retry: [];
}>();

const problem = computed(() => (isApiError(props.error) ? props.error.problem : null));
const retryAfterSeconds = computed(() =>
  isApiError(props.error) ? props.error.retryAfterSeconds : null,
);
const isGap = computed(() => problem.value?.code === "ENDPOINT_NOT_IMPLEMENTED");
const requiresManualRetry = computed(() =>
  requiresManualDatasourceOperationRetry(problem.value),
);
const manualRetryGuidance = computed(() =>
  datasourceOperationManualRetryGuidance(problem.value, retryAfterSeconds.value),
);
const alertTitle = computed(() => {
  if (props.title) return props.title;
  if (isGap.value) return "后端尚未实现此功能";
  return problem.value?.title ?? "请求未完成";
});
const description = computed(() => {
  if (isGap.value) {
    return "这个页面已接入正式 API 契约，但当前本机后端尚无对应路由。不会显示假数据或把按钮点击当成成功。";
  }
  if (problem.value?.detail) return problem.value.detail;
  return props.error instanceof Error ? props.error.message : "发生未知错误。";
});

function copyDiagnostics(): void {
  const text = [
    alertTitle.value,
    `code=${problem.value?.code ?? "CLIENT_ERROR"}`,
    `request_id=${problem.value?.request_id ?? "无"}`,
    description.value,
  ].join("\n");
  void navigator.clipboard?.writeText(text);
}

function fieldPath(field: { path?: string; field?: string }): string {
  return field.path ?? field.field ?? "请求字段";
}

</script>

<template>
  <section class="problem-panel" :class="{ 'problem-panel--gap': isGap }" role="alert">
    <div class="problem-panel__icon" aria-hidden="true">{{ isGap ? "⏸" : "!" }}</div>
    <div class="problem-panel__body">
      <strong>{{ alertTitle }}</strong>
      <p>{{ description }}</p>
      <p v-if="manualRetryGuidance" class="problem-panel__guidance">
        {{ manualRetryGuidance }}
      </p>
      <div class="problem-panel__meta">
        <code>{{ problem?.code ?? "CLIENT_ERROR" }}</code>
        <span v-if="problem?.request_id">request_id：{{ problem.request_id }}</span>
      </div>
      <ul v-if="problem?.field_errors?.length" class="problem-panel__fields">
        <li
          v-for="(field, index) in problem.field_errors"
          :key="`${fieldPath(field)}-${field.code ?? index}`"
        >
          <code>{{ fieldPath(field) }}</code>：{{ field.message }}
          <template v-if="field.code">（{{ field.code }}）</template>
        </li>
      </ul>
      <div class="problem-panel__actions">
        <el-button
          v-if="showRetry !== false && !requiresManualRetry"
          size="small"
          @click="emit('retry')"
        >
          重新请求
        </el-button>
        <el-button v-if="problem?.request_id" size="small" text @click="copyDiagnostics">
          复制诊断信息
        </el-button>
      </div>
    </div>
  </section>
</template>
