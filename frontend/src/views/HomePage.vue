<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";

import { getDashboard } from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import HealthPanel from "../components/HealthPanel.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime, shortId } from "../lib/display";
import type { DashboardResponse, HealthResponse, Project } from "../types";

const props = defineProps<{
  project: Project | null;
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: string | null;
}>();

const emit = defineEmits<{
  refreshHealth: [];
  openProjects: [];
  openExecution: [executionId: string];
}>();

const dashboard = ref<DashboardResponse | null>(null);
const loading = ref(false);
const error = ref<unknown>(null);

const successRate = computed(() => {
  const ratio = dashboard.value?.success_rate.ratio;
  return ratio === null || ratio === undefined ? "—" : `${(ratio * 100).toFixed(1)}%`;
});

async function load(): Promise<void> {
  if (!props.project) {
    dashboard.value = null;
    error.value = null;
    return;
  }
  loading.value = true;
  error.value = null;
  const to = new Date();
  const from = new Date(to.getTime() - 24 * 60 * 60 * 1000);
  try {
    dashboard.value = await getDashboard(props.project.id, from.toISOString(), to.toISOString());
  } catch (caught) {
    dashboard.value = null;
    error.value = caught;
  } finally {
    loading.value = false;
  }
}

onMounted(() => void load());
watch(() => props.project?.id, () => void load());
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">项目概览</p>
        <h1>首页</h1>
        <p>最近 24 小时的真实任务与执行事实；所有数量由当前项目的后端响应提供。</p>
      </div>
      <el-button :loading="loading" @click="load">刷新概览</el-button>
    </header>

    <EmptyState
      v-if="!project"
      title="尚未选择项目"
      description="先创建或选择一个真实项目，首页才会请求该项目的运行概览。"
      action-label="前往项目管理"
      @action="emit('openProjects')"
    />

    <template v-else>
      <section class="scope-strip">
        <div><span>当前项目</span><strong>{{ project.name }}</strong></div>
        <div><span>统计范围</span><strong>最近 24 小时</strong></div>
        <div><span>工作站</span><strong>Windows 本机 · 非 HA</strong></div>
      </section>

      <ProblemPanel v-if="error" :error="error" @retry="load" />

      <el-skeleton v-if="loading && !dashboard" :rows="5" animated />
      <template v-else-if="dashboard">
        <section class="metric-grid" aria-label="运行概览指标">
          <article class="metric-card">
            <span>可执行任务</span>
            <strong>{{ dashboard.job_counts.executable }}</strong>
            <small>未归档且已有发布版本</small>
          </article>
          <article class="metric-card">
            <span>24 小时执行数</span>
            <strong>{{ dashboard.execution_total }}</strong>
            <small>按 queued_at 统计</small>
          </article>
          <article class="metric-card">
            <span>已核验复制成功率</span>
            <strong>{{ successRate }}</strong>
            <small>
              {{ dashboard.success_rate.numerator }} / {{ dashboard.success_rate.denominator }} 个已结束复制
            </small>
          </article>
          <article class="metric-card">
            <span>运行中 / 核验中</span>
            <strong>
              {{ dashboard.execution_state_counts.RUNNING }} /
              {{ dashboard.execution_state_counts.VERIFYING }}
            </strong>
            <small>两个阶段分别统计</small>
          </article>
          <article class="metric-card">
            <span>恢复待处理</span>
            <strong>{{ dashboard.unresolved_failure_count }}</strong>
            <small>RecoveryGate 尚未核验</small>
          </article>
          <article class="metric-card">
            <span>已核验记录数</span>
            <strong>{{ dashboard.verified_records.value }}</strong>
            <small>{{ dashboard.verified_records.complete ? "证据完整" : "存在缺失的核验证据" }}</small>
          </article>
        </section>

        <section class="content-card">
          <div class="section-heading">
            <div>
              <span class="kicker">最近执行</span>
              <h2>执行事实</h2>
            </div>
            <span class="muted">生成于 {{ formatTime(dashboard.generated_at) }}</span>
          </div>
          <el-table :data="dashboard.recent_executions" empty-text="最近 24 小时没有执行">
            <el-table-column label="执行编号" min-width="150">
              <template #default="{ row }">
                <el-button link type="primary" @click="emit('openExecution', row.execution_id)">
                  {{ shortId(row.execution_id) }}
                </el-button>
              </template>
            </el-table-column>
            <el-table-column prop="job_name" label="复制任务" min-width="180" />
            <el-table-column label="进程状态" min-width="160">
              <template #default="{ row }">
                <StateBadge :value="row.process_state" kind="process" />
              </template>
            </el-table-column>
            <el-table-column label="数据影响" min-width="150">
              <template #default="{ row }">
                <StateBadge :value="row.data_effect" kind="effect" />
              </template>
            </el-table-column>
            <el-table-column label="独立核验" min-width="140">
              <template #default="{ row }">
                <StateBadge :value="row.verification_state" kind="verification" />
              </template>
            </el-table-column>
            <el-table-column label="排队时间" min-width="180">
              <template #default="{ row }">{{ formatTime(row.queued_at) }}</template>
            </el-table-column>
          </el-table>
        </section>

        <section class="content-card runtime-summary">
          <div>
            <span class="kicker">固定运行时</span>
            <h2>复制组件摘要</h2>
          </div>
          <div class="runtime-summary__items">
            <div><span>Worker</span><strong>{{ dashboard.runtime.worker_online ? "在线" : "离线" }}</strong></div>
            <div><span>DataX Runtime</span><strong>{{ dashboard.runtime.runtime_ready ? "就绪" : "阻断" }}</strong></div>
            <div><span>独立 oracle</span><strong>{{ dashboard.runtime.oracle_ready ? "就绪" : "阻断" }}</strong></div>
            <div><span>DataX 版本</span><strong>{{ dashboard.runtime.datax_release ?? "未确认" }}</strong></div>
          </div>
        </section>
      </template>

      <HealthPanel
        :health="health"
        :loading="healthLoading"
        :error="healthError"
        @refresh="emit('refreshHealth')"
      />
    </template>
  </div>
</template>
