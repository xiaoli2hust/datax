<script setup lang="ts">
import { computed } from "vue";

import type { HealthResponse } from "../types";

import StateBadge from "./StateBadge.vue";

const props = defineProps<{
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
  compact?: boolean;
}>();

const emit = defineEmits<{
  refresh: [];
}>();

const componentLabels: Record<string, string> = {
  postgres: "控制数据库",
  migrations: "数据库迁移",
  log_volume: "日志存储",
  worker: "执行 Worker",
  runtime: "DataX Runtime",
  oracle: "独立核验器",
  lifecycle: "恢复对账",
  dispatcher: "任务调度器",
  reconciler: "状态对账器",
  fencing: "执行围栏",
  worker_fencing: "执行围栏",
  workspace: "工作目录",
  workspace_volume: "工作目录",
  egress: "网络出口",
  egress_policy: "网络出口策略",
  keyrings: "密钥",
  audit: "审计",
  audit_chain: "审计链",
};

const entries = computed(() => Object.entries(props.health?.components ?? {}));
</script>

<template>
  <section class="health-panel" :class="{ 'health-panel--compact': compact }" aria-labelledby="health-title">
    <div class="section-heading">
      <div>
        <span class="kicker">真实运行状态</span>
        <h2 id="health-title">本机服务组件</h2>
      </div>
      <div class="inline-actions">
        <StateBadge v-if="health" :value="health.status" kind="generic" />
        <el-button :loading="loading" @click="emit('refresh')">重新检查</el-button>
      </div>
    </div>
    <el-alert
      v-if="error"
      type="error"
      :closable="false"
      show-icon
      title="无法连接本机状态接口"
      :description="error"
    />
    <div v-if="entries.length" class="health-grid">
      <article v-for="[name, component] in entries" :key="name" class="health-item">
        <div>
          <strong>{{ componentLabels[name] ?? name }}</strong>
          <code>{{ component.code }}</code>
        </div>
        <StateBadge :value="component.status" kind="generic" />
      </article>
    </div>
    <el-skeleton v-else :rows="compact ? 2 : 4" animated />
    <p v-if="health?.checked_at" class="muted">服务端检查时间：{{ health.checked_at }}</p>
  </section>
</template>
