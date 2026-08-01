<script setup lang="ts">
import { ElMessage, ElMessageBox } from "element-plus";
import { computed, onMounted, reactive, ref, watch } from "vue";

import { newIdempotencyKey } from "../api/client";
import {
  listJobs,
  listJobVersions,
  previewJob,
  publishJob,
  updateJob,
  validateJob,
} from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import JobWizard from "../components/JobWizard.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime, shortId } from "../lib/display";
import type {
  JobPreview,
  JobVersion,
  SyncJob,
  ValidationReport,
} from "../types";

const props = defineProps<{
  projectId: string;
  canDevelop: boolean;
  canOperate: boolean;
}>();

const emit = defineEmits<{
  run: [jobId: string];
}>();

const items = ref<SyncJob[]>([]);
const loading = ref(false);
const loadingMore = ref(false);
const error = ref<unknown>(null);
const nextCursor = ref<string | null>(null);
const hasMore = ref(false);
const filters = reactive({
  query: "",
  status: "",
  readerPlugin: "",
  writerPlugin: "",
  latestExecutionState: "",
});
const wizardVisible = ref(false);
const editingJob = ref<SyncJob | null>(null);
const actionId = ref<string | null>(null);
const reportVisible = ref(false);
const report = ref<ValidationReport | null>(null);
const previewVisible = ref(false);
const preview = ref<JobPreview | null>(null);
const versionsVisible = ref(false);
const versions = ref<JobVersion[]>([]);
const versionsNextCursor = ref<string | null>(null);
const versionsHasMore = ref(false);
const versionsLoading = ref(false);
const compareLeftId = ref("");
const compareRightId = ref("");
const selectedJob = ref<SyncJob | null>(null);
const publishKeys = new Map<string, string>();

async function load(append = false): Promise<void> {
  if (append) loadingMore.value = true;
  else loading.value = true;
  error.value = null;
  try {
    const page = await listJobs(props.projectId, {
      query: filters.query.trim() || undefined,
      status: (filters.status || undefined) as SyncJob["status"] | undefined,
      readerPlugin: (filters.readerPlugin || undefined) as
        | "mysqlreader"
        | "postgresqlreader"
        | undefined,
      writerPlugin: (filters.writerPlugin || undefined) as
        | "mysqlwriter"
        | "postgresqlwriter"
        | undefined,
      latestExecutionState: (filters.latestExecutionState || undefined) as
        | import("../types").ProcessState
        | undefined,
      cursor: append ? nextCursor.value ?? undefined : undefined,
    });
    items.value = append ? [...items.value, ...page.items] : page.items;
    nextCursor.value = page.next_cursor;
    hasMore.value = page.has_more;
  } catch (caught) {
    error.value = caught;
    if (!append) items.value = [];
  } finally {
    if (append) loadingMore.value = false;
    else loading.value = false;
  }
}

function resetFilters(): void {
  filters.query = "";
  filters.status = "";
  filters.readerPlugin = "";
  filters.writerPlugin = "";
  filters.latestExecutionState = "";
  void load();
}

async function runValidation(job: SyncJob): Promise<void> {
  actionId.value = job.id;
  error.value = null;
  try {
    report.value = await validateJob(job.id);
    reportVisible.value = true;
    if (report.value.valid) ElMessage.success("服务端校验通过，可发布新版本。");
    else ElMessage.warning("服务端校验完成，仍有阻断问题。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    actionId.value = null;
  }
}

async function openPreview(job: SyncJob): Promise<void> {
  actionId.value = job.id;
  error.value = null;
  try {
    preview.value = await previewJob(job.id);
    previewVisible.value = true;
  } catch (caught) {
    error.value = caught;
  } finally {
    actionId.value = null;
  }
}

async function publish(job: SyncJob): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `将当前已校验草稿发布为不可变版本。发布不会自动运行任务。草稿哈希：${job.draft_spec_hash.slice(0, 12)}…`,
      "发布不可变版本",
      {
        confirmButtonText: "发布版本",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    actionId.value = job.id;
    const idempotencyKey = publishKeys.get(job.id) ?? newIdempotencyKey();
    publishKeys.set(job.id, idempotencyKey);
    const version = await publishJob(job, idempotencyKey);
    publishKeys.delete(job.id);
    ElMessage.success(`版本 v${version.version_no} 已发布；尚未运行。`);
    await load();
  } catch (caught) {
    if (caught !== "cancel" && caught !== "close") error.value = caught;
  } finally {
    actionId.value = null;
  }
}

async function openVersions(job: SyncJob): Promise<void> {
  selectedJob.value = job;
  actionId.value = job.id;
  error.value = null;
  versions.value = [];
  versionsNextCursor.value = null;
  versionsHasMore.value = false;
  compareLeftId.value = "";
  compareRightId.value = "";
  try {
    await loadVersions();
    versionsVisible.value = true;
  } catch (caught) {
    error.value = caught;
  } finally {
    actionId.value = null;
  }
}

async function loadVersions(append = false): Promise<void> {
  if (!selectedJob.value) return;
  versionsLoading.value = true;
  try {
    const page = await listJobVersions(
      selectedJob.value.id,
      append ? versionsNextCursor.value ?? undefined : undefined,
    );
    versions.value = append
      ? [...versions.value, ...page.items]
      : page.items;
    versionsNextCursor.value = page.next_cursor;
    versionsHasMore.value = page.has_more;
    if (!append && versions.value.length >= 2) {
      compareLeftId.value = versions.value[1]?.id ?? "";
      compareRightId.value = versions.value[0]?.id ?? "";
    }
  } finally {
    versionsLoading.value = false;
  }
}

function openEditor(job?: SyncJob): void {
  editingJob.value = job ?? null;
  wizardVisible.value = true;
}

async function archive(job: SyncJob): Promise<void> {
  try {
    await ElMessageBox.confirm(
      "归档后不能创建新执行，历史版本、执行与审计仍保持只读可见。若存在进行中执行，服务端会拒绝。",
      `归档任务“${job.name}”`,
      {
        confirmButtonText: "确认归档",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    actionId.value = job.id;
    await updateJob(job, { status: "ARCHIVED" });
    ElMessage.success("任务已归档，历史事实保持不变。");
    await load();
  } catch (caught) {
    if (caught !== "cancel" && caught !== "close") error.value = caught;
  } finally {
    actionId.value = null;
  }
}

interface VersionDifference {
  path: string;
  left: string;
  right: string;
}

const versionDifferences = computed<VersionDifference[]>(() => {
  const left = versions.value.find((version) => version.id === compareLeftId.value);
  const right = versions.value.find((version) => version.id === compareRightId.value);
  if (!left || !right || left.id === right.id) return [];
  const leftValues = flattenVersion(left);
  const rightValues = flattenVersion(right);
  const paths = new Set([...leftValues.keys(), ...rightValues.keys()]);
  return [...paths]
    .sort()
    .filter((path) => leftValues.get(path) !== rightValues.get(path))
    .map((path) => ({
      path,
      left: leftValues.get(path) ?? "（不存在）",
      right: rightValues.get(path) ?? "（不存在）",
    }));
});

function flattenVersion(version: JobVersion): Map<string, string> {
  const flattened = new Map<string, string>();
  const walk = (value: unknown, path: string): void => {
    if (value !== null && typeof value === "object") {
      if (Array.isArray(value)) {
        value.forEach((item, index) => walk(item, `${path}[${index}]`));
      } else {
        Object.entries(value as Record<string, unknown>).forEach(
          ([key, item]) => walk(item, path ? `${path}.${key}` : key),
        );
      }
      return;
    }
    const sensitive = /(password|secret|token|credential)/i.test(path);
    flattened.set(
      path,
      sensitive ? "••••••" : value === null ? "null" : String(value),
    );
  };
  walk(
    {
      spec: version.spec,
      spec_hash: version.spec_hash,
      version_artifact_hash: version.version_artifact_hash,
      runtime: version.datax_release,
      reader_plugin: version.reader_plugin,
      writer_plugin: version.writer_plugin,
    },
    "",
  );
  return flattened;
}

function endpointSummary(job: SyncJob): string {
  const source = job.draft_spec.source;
  const target = job.draft_spec.target;
  return `${source.table.schema_name}.${source.table.table_name} → ${target.table.schema_name}.${target.table.table_name}`;
}

onMounted(() => void load());
watch(() => props.projectId, () => void load());
watch(wizardVisible, (visible) => {
  if (!visible) editingJob.value = null;
});
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">设计与发布</p>
        <h1>复制任务</h1>
        <p>任务草稿可修改；只有经真实校验后发布的不可变 JobVersion 才能执行。</p>
      </div>
      <el-button v-if="canDevelop" type="primary" @click="openEditor()">新建复制任务</el-button>
    </header>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      title="V1 只支持单表一次性复制"
      description="没有调度、DAG、任意 SQL、脚本转换、插件上传或 DataX JSON 导入入口。"
    />
    <el-alert
      v-if="!canDevelop"
      type="info"
      :closable="false"
      show-icon
      title="当前为只读任务视图"
      description="你可以查看草稿摘要、不可变版本、发布人和差异，但服务端不会允许编辑、校验、发布或归档。"
    />
    <section class="filter-bar">
      <el-input
        v-model="filters.query"
        clearable
        placeholder="任务名或源/目标表名"
        @keyup.enter="load()"
      />
      <el-select v-model="filters.status" clearable placeholder="全部任务状态" @change="load()">
        <el-option label="草稿" value="DRAFT" />
        <el-option label="已校验" value="VALID" />
        <el-option label="已发布" value="PUBLISHED" />
        <el-option label="已归档" value="ARCHIVED" />
      </el-select>
      <el-select v-model="filters.readerPlugin" clearable placeholder="全部 Reader" @change="load()">
        <el-option label="MySQL 8 Reader" value="mysqlreader" />
        <el-option label="PostgreSQL 15 Reader" value="postgresqlreader" />
      </el-select>
      <el-select v-model="filters.writerPlugin" clearable placeholder="全部 Writer" @change="load()">
        <el-option label="MySQL 8 Writer" value="mysqlwriter" />
        <el-option label="PostgreSQL 15 Writer" value="postgresqlwriter" />
      </el-select>
      <el-select
        v-model="filters.latestExecutionState"
        clearable
        placeholder="最近执行状态"
        @change="load()"
      >
        <el-option label="排队中" value="QUEUED" />
        <el-option label="启动中" value="STARTING" />
        <el-option label="运行中" value="RUNNING" />
        <el-option label="核验中" value="VERIFYING" />
        <el-option label="已核验成功" value="SUCCEEDED" />
        <el-option label="失败" value="FAILED" />
        <el-option label="超时" value="TIMED_OUT" />
        <el-option label="取消请求中" value="CANCEL_REQUESTED" />
        <el-option label="已取消" value="CANCELED" />
        <el-option label="状态丢失" value="LOST" />
      </el-select>
      <el-button :loading="loading" @click="load()">筛选</el-button>
      <el-button @click="resetFilters">重置</el-button>
    </section>
    <ProblemPanel v-if="error" :error="error" @retry="load" />
    <el-skeleton v-if="loading && !items.length" :rows="6" animated />
    <EmptyState
      v-else-if="!items.length && !error"
      title="当前项目还没有复制任务"
      :description="
        canDevelop
          ? '使用已授权数据源和真实元数据创建第一个任务草稿。'
          : 'Admin 或 Developer 尚未为本项目发布复制任务。'
      "
      :action-label="canDevelop ? '新建复制任务' : undefined"
      @action="openEditor()"
    />

    <section v-else class="content-card">
      <el-table :data="items" row-key="id">
        <el-table-column label="任务" min-width="230">
          <template #default="{ row }">
            <div class="primary-cell">
              <strong>{{ row.name }}</strong>
              <span>{{ row.description || "无说明" }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="源表 → 目标表" min-width="280">
          <template #default="{ row }"><code>{{ endpointSummary(row) }}</code></template>
        </el-table-column>
        <el-table-column label="状态" width="130">
          <template #default="{ row }"><StateBadge :value="row.status" kind="job" /></template>
        </el-table-column>
        <el-table-column label="当前草稿" min-width="160">
          <template #default="{ row }">
            <div class="primary-cell">
              <code>{{ row.draft_spec_hash.slice(0, 12) }}…</code>
              <span>
                {{
                  row.validated_spec_hash === row.draft_spec_hash
                    ? "当前草稿已通过校验"
                    : "当前草稿尚未通过校验"
                }}
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="最新发布版本" min-width="160">
          <template #default="{ row }">
            <code v-if="row.latest_published_version_id">
              v{{ row.latest_published_version_no ?? "?" }} ·
              {{ shortId(row.latest_published_version_id) }}
            </code>
            <span v-else>尚未发布</span>
          </template>
        </el-table-column>
        <el-table-column label="最近执行" min-width="180">
          <template #default="{ row }">
            <div v-if="row.latest_execution_process_state" class="primary-cell">
              <StateBadge :value="row.latest_execution_process_state" kind="process" />
              <span>{{ formatTime(row.latest_execution_at) }}</span>
            </div>
            <span v-else>尚未执行</span>
          </template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" min-width="360" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="canDevelop && row.status !== 'ARCHIVED'"
              size="small"
              @click="openEditor(row)"
            >
              编辑草稿
            </el-button>
            <el-button
              v-if="canDevelop && row.status !== 'ARCHIVED'"
              size="small"
              :loading="actionId === row.id"
              @click="runValidation(row)"
            >
              校验
            </el-button>
            <el-button
              v-if="canDevelop"
              size="small"
              :loading="actionId === row.id"
              @click="openPreview(row)"
            >
              脱敏预览
            </el-button>
            <el-button
              v-if="canDevelop && row.status === 'VALID'"
              size="small"
              type="primary"
              :loading="actionId === row.id"
              @click="publish(row)"
            >
              发布
            </el-button>
            <el-button size="small" :loading="actionId === row.id" @click="openVersions(row)">版本</el-button>
            <el-button
              v-if="canOperate && row.latest_published_version_id && row.status !== 'ARCHIVED'"
              size="small"
              type="success"
              plain
              @click="emit('run', row.id)"
            >
              运行已发布版本
            </el-button>
            <el-button
              v-if="canDevelop && row.status !== 'ARCHIVED'"
              size="small"
              type="danger"
              plain
              :loading="actionId === row.id"
              @click="archive(row)"
            >
              归档
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="hasMore" class="load-more">
        <el-button :loading="loadingMore" @click="load(true)">加载下一页</el-button>
      </div>
    </section>

    <JobWizard
      v-model="wizardVisible"
      :project-id="projectId"
      :job="editingJob"
      @saved="load"
    />

    <el-drawer v-model="reportVisible" title="任务校验结果" size="min(700px, 96vw)">
      <template v-if="report">
        <el-alert
          :type="report.valid ? 'success' : 'error'"
          :title="report.valid ? '校验通过，可发布新版本' : '校验未通过，不能发布'"
          :closable="false"
          show-icon
        />
        <dl class="detail-list">
          <div><dt>草稿哈希</dt><dd><code>{{ report.draft_spec_hash }}</code></dd></div>
          <div><dt>源 Schema 哈希</dt><dd><code>{{ report.source_schema_hash ?? "未形成" }}</code></dd></div>
          <div><dt>目标 Schema 哈希</dt><dd><code>{{ report.target_schema_hash ?? "未形成" }}</code></dd></div>
        </dl>
        <section v-if="report.errors.length" class="issue-list">
          <h3>阻断问题</h3>
          <article v-for="issue in report.errors" :key="`${issue.path}-${issue.code}`">
            <strong>{{ issue.message }}</strong>
            <span><code>{{ issue.path }}</code> · {{ issue.code }}</span>
          </article>
        </section>
        <section v-if="report.warnings.length" class="issue-list issue-list--warning">
          <h3>警告</h3>
          <article v-for="issue in report.warnings" :key="`${issue.path}-${issue.code}`">
            <strong>{{ issue.message }}</strong>
            <span><code>{{ issue.path }}</code> · {{ issue.code }}</span>
          </article>
        </section>
      </template>
    </el-drawer>

    <el-drawer v-model="previewVisible" title="已脱敏、不可执行的 DataX JSON" size="min(760px, 96vw)">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="只读预览"
        description="此响应由后端完成脱敏，executable 固定为 false；前端不会把它保存成可执行配置。"
      />
      <pre v-if="preview" class="json-preview">{{ JSON.stringify(preview.redacted_datax_json, null, 2) }}</pre>
    </el-drawer>

    <el-drawer
      v-model="versionsVisible"
      :title="`${selectedJob?.name ?? ''} · 已发布版本`"
      size="min(760px, 96vw)"
    >
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="历史版本不可修改"
        description="版本详情和差异只读展示不可变 JobSpec、制品哈希与 Runtime/插件事实；当前契约未把可变任务名称/说明写入 JobVersion，因此不会伪装历史名称差异。凭据类字段统一遮蔽。"
      />
      <el-table v-loading="versionsLoading" :data="versions" empty-text="尚无已发布版本">
        <el-table-column label="版本" width="100">
          <template #default="{ row }">v{{ row.version_no }}</template>
        </el-table-column>
        <el-table-column label="版本 ID" min-width="170">
          <template #default="{ row }"><code>{{ shortId(row.id) }}</code></template>
        </el-table-column>
        <el-table-column label="配置哈希" min-width="170">
          <template #default="{ row }"><code>{{ row.spec_hash.slice(0, 16) }}…</code></template>
        </el-table-column>
        <el-table-column prop="datax_release" label="Runtime" width="150" />
        <el-table-column label="发布人" min-width="150">
          <template #default="{ row }"><code>{{ shortId(row.published_by) }}</code></template>
        </el-table-column>
        <el-table-column label="发布时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.published_at) }}</template>
        </el-table-column>
      </el-table>
      <div v-if="versionsHasMore" class="load-more">
        <el-button :loading="versionsLoading" @click="loadVersions(true)">加载更早版本</el-button>
      </div>

      <section v-if="versions.length >= 2" class="content-card">
        <h3>版本差异</h3>
        <div class="form-grid form-grid--two">
          <el-select v-model="compareLeftId" placeholder="较早版本">
            <el-option
              v-for="version in versions"
              :key="version.id"
              :label="`v${version.version_no}`"
              :value="version.id"
            />
          </el-select>
          <el-select v-model="compareRightId" placeholder="较新版本">
            <el-option
              v-for="version in versions"
              :key="version.id"
              :label="`v${version.version_no}`"
              :value="version.id"
            />
          </el-select>
        </div>
        <el-alert
          v-if="compareLeftId === compareRightId"
          type="warning"
          :closable="false"
          title="请选择两个不同版本"
        />
        <el-empty
          v-else-if="versionDifferences.length === 0"
          description="两个版本的可展示配置没有差异"
        />
        <el-table v-else :data="versionDifferences" max-height="360">
          <el-table-column prop="path" label="字段" min-width="240" />
          <el-table-column prop="left" label="较早版本" min-width="220" />
          <el-table-column prop="right" label="较新版本" min-width="220" />
        </el-table>
      </section>
    </el-drawer>
  </div>
</template>
