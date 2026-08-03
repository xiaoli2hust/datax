<script setup lang="ts">
import { ElMessage, ElMessageBox } from "element-plus";
import { computed, onMounted, reactive, ref, watch } from "vue";

import {
  isApiError,
  newIdempotencyKey,
  requiresManualDatasourceOperationRetry,
} from "../api/client";
import {
  createDatasource,
  deleteDatasource,
  getDatasourceAdminDetail,
  listDatasourceTables,
  listDatasources,
  listEndpointPolicies,
  testDatasource,
  updateDatasource,
  type DatasourcePatchInput,
} from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import type {
  DatasourceAdminDetail,
  DatasourceSummary,
  DatasourceTestResult,
  DatasourceUsage,
  EndpointPolicySummary,
  Engine,
  TableSchema,
} from "../types";

type SslMode = DatasourceAdminDetail["current_revision"]["ssl_mode"];

const props = defineProps<{
  projectId: string;
  canAdmin: boolean;
  canReadMetadata: boolean;
  egressReady: boolean;
}>();

const items = ref<DatasourceSummary[]>([]);
const loading = ref(false);
const loadingMore = ref(false);
const nextCursor = ref<string | null>(null);
const hasMore = ref(false);
const error = ref<unknown>(null);
const createVisible = ref(false);
const editVisible = ref(false);
const editLoading = ref(false);
const editOriginal = ref<DatasourceAdminDetail | null>(null);
const rotateVisible = ref(false);
const rotateTarget = ref<DatasourceSummary | null>(null);
const rotatePassword = ref("");
const rotateConfirmation = ref("");
const submitting = ref(false);
const operationId = ref<string | null>(null);
const policies = ref<EndpointPolicySummary[]>([]);
const policyError = ref<unknown>(null);
const detailVisible = ref(false);
const detailLoading = ref(false);
const detail = ref<DatasourceAdminDetail | null>(null);
const detailError = ref<unknown>(null);
const testResults = reactive<Record<string, DatasourceTestResult>>({});
const testingId = ref<string | null>(null);
const metadataVisible = ref(false);
const metadataLoading = ref(false);
const metadataLoadingMore = ref(false);
const metadataLoadingAll = ref(false);
const metadataError = ref<unknown>(null);
const metadataDatasource = ref<DatasourceSummary | null>(null);
const metadataUsage = ref<DatasourceUsage | null>(null);
const metadataNextCursor = ref<string | null>(null);
const metadataHasMore = ref(false);
const tables = ref<TableSchema[]>([]);
const metadataRequestToken = ref(0);
const createKey = ref(newIdempotencyKey());

const form = reactive({
  name: "",
  description: "",
  endpointPolicyId: "",
  engine: "MYSQL_8" as Engine,
  host: "",
  port: 3306,
  databaseName: "",
  defaultSchema: "",
  username: "",
  password: "",
  sslMode: "REQUIRE" as SslMode,
});

const editForm = reactive({
  name: "",
  description: "",
  endpointPolicyId: "",
  engine: "MYSQL_8" as Engine,
  host: "",
  port: 3306,
  databaseName: "",
  defaultSchema: "",
  username: "",
  sslMode: "REQUIRE" as SslMode,
});

const activePolicies = computed(() =>
  policies.value.filter((policy) => policy.status === "ACTIVE"),
);
const metadataRequiresExplicitRetry = computed(
  () =>
    isApiError(metadataError.value) &&
    requiresManualDatasourceOperationRetry(metadataError.value.problem),
);
const createPolicies = computed(() =>
  activePolicies.value.filter((policy) => policy.current_revision.engine === form.engine),
);
const editPolicies = computed(() =>
  activePolicies.value.filter((policy) => policy.current_revision.engine === editForm.engine),
);
const canSubmit = computed(
  () =>
    form.name.trim().length > 0 &&
    form.endpointPolicyId.length > 0 &&
    form.host.trim().length > 0 &&
    form.port >= 1 &&
    form.port <= 65535 &&
    form.databaseName.trim().length > 0 &&
    form.defaultSchema.trim().length > 0 &&
    form.username.trim().length > 0 &&
    form.password.length > 0,
);
const canSubmitEdit = computed(
  () =>
    editOriginal.value !== null &&
    editForm.name.trim().length > 0 &&
    editForm.endpointPolicyId.length > 0 &&
    editForm.host.trim().length > 0 &&
    editForm.port >= 1 &&
    editForm.port <= 65535 &&
    editForm.databaseName.trim().length > 0 &&
    editForm.defaultSchema.trim().length > 0 &&
    editForm.username.trim().length > 0,
);
const canRotate = computed(
  () =>
    rotatePassword.value.length > 0 &&
    rotatePassword.value === rotateConfirmation.value &&
    props.egressReady,
);

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const page = await listDatasources(props.projectId);
    items.value = page.items;
    nextCursor.value = page.next_cursor;
    hasMore.value = page.has_more;
  } catch (caught) {
    error.value = caught;
    items.value = [];
    nextCursor.value = null;
    hasMore.value = false;
  } finally {
    loading.value = false;
  }
}

async function loadMore(): Promise<void> {
  if (!hasMore.value || !nextCursor.value || loadingMore.value) return;
  loadingMore.value = true;
  error.value = null;
  try {
    const page = await listDatasources(props.projectId, nextCursor.value);
    items.value.push(...page.items);
    nextCursor.value = page.next_cursor;
    hasMore.value = page.has_more;
  } catch (caught) {
    error.value = caught;
  } finally {
    loadingMore.value = false;
  }
}

async function loadPolicies(): Promise<void> {
  policyError.value = null;
  try {
    policies.value = (await listEndpointPolicies()).items;
  } catch (caught) {
    policyError.value = caught;
    policies.value = [];
  }
}

async function openCreate(): Promise<void> {
  form.name = "";
  form.description = "";
  form.endpointPolicyId = "";
  form.engine = "MYSQL_8";
  form.host = "";
  form.port = 3306;
  form.databaseName = "";
  form.defaultSchema = "";
  form.username = "";
  form.password = "";
  form.sslMode = "REQUIRE";
  createKey.value = newIdempotencyKey();
  error.value = null;
  createVisible.value = true;
  await loadPolicies();
}

function engineChanged(): void {
  form.port = form.engine === "MYSQL_8" ? 3306 : 5432;
  form.endpointPolicyId = "";
  if (form.engine === "MYSQL_8") form.defaultSchema = form.databaseName;
  else if (!form.defaultSchema) form.defaultSchema = "public";
}

function editEngineChanged(): void {
  editForm.port = editForm.engine === "MYSQL_8" ? 3306 : 5432;
  editForm.endpointPolicyId = "";
  if (editForm.engine === "MYSQL_8") editForm.defaultSchema = editForm.databaseName;
  else if (!editForm.defaultSchema) editForm.defaultSchema = "public";
}

async function submitCreate(): Promise<void> {
  if (!canSubmit.value) return;
  submitting.value = true;
  error.value = null;
  try {
    await createDatasource(
      props.projectId,
      {
        name: form.name.trim(),
        description: form.description.trim() || null,
        endpoint_policy_id: form.endpointPolicyId,
        engine: form.engine,
        host: form.host.trim(),
        port: form.port,
        database_name: form.databaseName.trim(),
        default_schema: form.defaultSchema.trim(),
        username: form.username.trim(),
        password: form.password,
        ssl_mode: form.sslMode,
      },
      createKey.value,
    );
    createVisible.value = false;
    form.password = "";
    ElMessage.success("数据源已创建；连接、身份与出口策略已由服务端真实验证。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
    form.password = "";
  }
}

async function openEdit(item: DatasourceSummary): Promise<void> {
  if (!props.canAdmin) return;
  editVisible.value = true;
  editLoading.value = true;
  error.value = null;
  editOriginal.value = null;
  try {
    const [current] = await Promise.all([
      getDatasourceAdminDetail(item.id),
      loadPolicies(),
    ]);
    const matchingPolicy = policies.value.find(
      (policy) =>
        policy.current_revision_id === current.current_revision.endpoint_policy_revision_id,
    );
    editOriginal.value = current;
    editForm.name = current.name;
    editForm.description = current.description ?? "";
    editForm.endpointPolicyId = matchingPolicy?.id ?? "";
    editForm.engine = current.current_revision.engine;
    editForm.host = current.current_revision.host;
    editForm.port = current.current_revision.port;
    editForm.databaseName = current.current_revision.database_name;
    editForm.defaultSchema = current.current_revision.default_schema;
    editForm.username = current.current_revision.username;
    editForm.sslMode = current.current_revision.ssl_mode;
  } catch (caught) {
    error.value = caught;
  } finally {
    editLoading.value = false;
  }
}

async function submitEdit(): Promise<void> {
  const original = editOriginal.value;
  if (!original || !canSubmitEdit.value) return;
  const revision = original.current_revision;
  const currentPolicy = policies.value.find(
    (policy) => policy.current_revision_id === revision.endpoint_policy_revision_id,
  );
  const patch: DatasourcePatchInput = {};
  const normalizedName = editForm.name.trim();
  const normalizedDescription = editForm.description.trim() || null;
  if (normalizedName !== original.name) patch.name = normalizedName;
  if (normalizedDescription !== original.description) patch.description = normalizedDescription;
  if (editForm.endpointPolicyId !== currentPolicy?.id) {
    patch.endpoint_policy_id = editForm.endpointPolicyId;
  }
  if (editForm.engine !== revision.engine) patch.engine = editForm.engine;
  if (editForm.host.trim() !== revision.host) patch.host = editForm.host.trim();
  if (editForm.port !== revision.port) patch.port = editForm.port;
  if (editForm.databaseName.trim() !== revision.database_name) {
    patch.database_name = editForm.databaseName.trim();
  }
  if (editForm.defaultSchema.trim() !== revision.default_schema) {
    patch.default_schema = editForm.defaultSchema.trim();
  }
  if (editForm.username.trim() !== revision.username) patch.username = editForm.username.trim();
  if (editForm.sslMode !== revision.ssl_mode) patch.ssl_mode = editForm.sslMode;
  if (!Object.keys(patch).length) {
    ElMessage.info("连接配置没有变化。");
    return;
  }
  if (
    !props.egressReady &&
    Object.keys(patch).some((field) =>
      [
        "endpoint_policy_id",
        "engine",
        "host",
        "port",
        "database_name",
        "default_schema",
        "username",
        "ssl_mode",
      ].includes(field),
    )
  ) {
    ElMessage.error("本机网络出口策略未就绪，不能保存未经真实验证的连接修订。");
    return;
  }
  submitting.value = true;
  error.value = null;
  try {
    await updateDatasource(original, patch);
    editVisible.value = false;
    ElMessage.success("数据源已更新；连接字段变化已生成新的不可变修订。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
  }
}

async function runTest(item: DatasourceSummary): Promise<void> {
  if (!props.egressReady) {
    ElMessage.error("本机网络出口策略尚未就绪，不能发起真实连接测试。");
    return;
  }
  testingId.value = item.id;
  error.value = null;
  try {
    const result = await testDatasource(item.id);
    testResults[item.id] = result;
    if (result.status === "SUCCEEDED") ElMessage.success("真实连接测试通过。");
    else ElMessage.warning("连接测试已完成，但数据库连接失败。请查看稳定错误码。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    testingId.value = null;
  }
}

async function changeStatus(item: DatasourceSummary): Promise<void> {
  const nextStatus = item.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
  if (nextStatus === "ACTIVE" && !props.egressReady) {
    ElMessage.error("网络出口策略未就绪，不能恢复数据源。");
    return;
  }
  try {
    await ElMessageBox.confirm(
      nextStatus === "DISABLED"
        ? `停用“${item.name}”后将阻断新发布和新执行，历史记录仍保留。`
        : `恢复“${item.name}”会先执行真实连接、身份与出口策略验证。`,
      nextStatus === "DISABLED" ? "确认停用" : "确认恢复",
      { type: "warning", confirmButtonText: "确认", cancelButtonText: "取消" },
    );
  } catch {
    return;
  }
  operationId.value = item.id;
  error.value = null;
  try {
    await updateDatasource(item, { status: nextStatus });
    ElMessage.success(nextStatus === "DISABLED" ? "数据源已停用。" : "数据源已验证并恢复。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    operationId.value = null;
  }
}

function openRotate(item: DatasourceSummary): void {
  rotateTarget.value = item;
  rotatePassword.value = "";
  rotateConfirmation.value = "";
  rotateVisible.value = true;
}

async function submitRotate(): Promise<void> {
  const target = rotateTarget.value;
  if (!target || !canRotate.value) return;
  submitting.value = true;
  error.value = null;
  try {
    await updateDatasource(target, { password: rotatePassword.value });
    rotateVisible.value = false;
    ElMessage.success("新凭据已通过真实连接验证并切换；旧凭据版本保留为可追溯历史。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
    rotatePassword.value = "";
    rotateConfirmation.value = "";
  }
}

async function removeDatasource(item: DatasourceSummary): Promise<void> {
  let confirmation: { value: string };
  try {
    confirmation = await ElMessageBox.prompt(
      `软删除会保留历史修订和审计；存在活动任务或执行引用时服务端会拒绝。请输入“${item.name}”确认。`,
      "确认删除数据源",
      {
        type: "warning",
        inputPlaceholder: item.name,
        inputValidator: (value: string) => value === item.name || "名称不匹配",
        confirmButtonText: "软删除",
        cancelButtonText: "取消",
      },
    );
  } catch {
    return;
  }
  if (confirmation.value !== item.name) return;
  operationId.value = item.id;
  error.value = null;
  try {
    await deleteDatasource(item);
    ElMessage.success("数据源已软删除；历史修订与审计仍保留。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    operationId.value = null;
  }
}

async function openDetail(item: DatasourceSummary): Promise<void> {
  detailVisible.value = true;
  detailLoading.value = true;
  detail.value = null;
  detailError.value = null;
  try {
    detail.value = await getDatasourceAdminDetail(item.id);
  } catch (caught) {
    detailError.value = caught;
  } finally {
    detailLoading.value = false;
  }
}

async function loadMetadataPage(append: boolean): Promise<void> {
  const target = metadataDatasource.value;
  const usage = metadataUsage.value;
  if (!target || !usage) return;
  const requestToken = metadataRequestToken.value;
  const requestIsCurrent = (): boolean =>
    metadataRequestToken.value === requestToken &&
    metadataDatasource.value?.id === target.id &&
    metadataUsage.value === usage;
  if (append) metadataLoadingMore.value = true;
  else metadataLoading.value = true;
  metadataError.value = null;
  try {
    const page = await listDatasourceTables(target.id, {
      usage,
      cursor: append ? (metadataNextCursor.value ?? undefined) : undefined,
    });
    if (!requestIsCurrent()) return;
    if (append) tables.value.push(...page.items);
    else tables.value = page.items;
    metadataNextCursor.value = page.next_cursor;
    metadataHasMore.value = page.has_more;
  } catch (caught) {
    if (requestIsCurrent()) metadataError.value = caught;
  } finally {
    if (requestIsCurrent()) {
      metadataLoading.value = false;
      metadataLoadingMore.value = false;
    }
  }
}

function openMetadata(item: DatasourceSummary): void {
  if (!props.egressReady) {
    ElMessage.error("本机网络出口策略尚未就绪，不能读取数据库元数据。");
    return;
  }
  metadataRequestToken.value += 1;
  metadataLoading.value = false;
  metadataLoadingMore.value = false;
  metadataLoadingAll.value = false;
  metadataVisible.value = true;
  metadataDatasource.value = item;
  metadataUsage.value = null;
  metadataError.value = null;
  metadataNextCursor.value = null;
  metadataHasMore.value = false;
  tables.value = [];
}

async function loadMetadataForUsage(usage: DatasourceUsage): Promise<void> {
  if (
    metadataLoading.value ||
    metadataLoadingMore.value ||
    metadataLoadingAll.value
  ) {
    return;
  }
  metadataRequestToken.value += 1;
  metadataUsage.value = usage;
  metadataError.value = null;
  metadataNextCursor.value = null;
  metadataHasMore.value = false;
  tables.value = [];
  await loadMetadataPage(false);
}

async function loadAllMetadata(): Promise<void> {
  if (!metadataHasMore.value || metadataLoadingAll.value) return;
  const target = metadataDatasource.value;
  const usage = metadataUsage.value;
  if (!target || !usage) return;
  const requestToken = metadataRequestToken.value;
  const requestIsCurrent = (): boolean =>
    metadataRequestToken.value === requestToken &&
    metadataDatasource.value?.id === target.id &&
    metadataUsage.value === usage;
  metadataLoadingAll.value = true;
  const seen = new Set<string>();
  try {
    while (
      requestIsCurrent() &&
      metadataHasMore.value &&
      metadataNextCursor.value
    ) {
      const cursor = metadataNextCursor.value;
      if (seen.has(cursor)) throw new Error("服务端返回了重复分页游标，已停止加载。");
      seen.add(cursor);
      await loadMetadataPage(true);
      if (!requestIsCurrent()) return;
      if (metadataError.value) break;
    }
  } catch (caught) {
    if (requestIsCurrent()) metadataError.value = caught;
  } finally {
    if (requestIsCurrent()) metadataLoadingAll.value = false;
  }
}

async function retryMetadata(): Promise<void> {
  const usage = metadataUsage.value;
  if (!usage) return;
  await loadMetadataForUsage(usage);
}

function closeMetadata(): void {
  metadataRequestToken.value += 1;
  metadataLoading.value = false;
  metadataLoadingMore.value = false;
  metadataLoadingAll.value = false;
  metadataDatasource.value = null;
  metadataUsage.value = null;
  metadataError.value = null;
  metadataNextCursor.value = null;
  metadataHasMore.value = false;
  tables.value = [];
}

onMounted(() => void load());
watch(
  () => props.projectId,
  () => void load(),
);
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">项目资源</p>
        <h1>数据源</h1>
        <p>仅 MySQL 8 与 PostgreSQL 15；项目成员默认只接收不可逆脱敏端点摘要。</p>
      </div>
      <el-button v-if="canAdmin" type="primary" @click="openCreate">新建数据源</el-button>
    </header>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      title="权限说明"
      description="只有 Admin 能创建、查看完整连接定位和测试数据源。隐藏按钮只是辅助，服务端权限才是最终边界。"
    />
    <el-alert
      v-if="!egressReady"
      type="error"
      :closable="false"
      show-icon
      title="本机网络出口策略尚未就绪"
      description="可以先保存数据源配置，但不能测试连接、读取真实元数据或据此判断数据源可用。请先在 Windows 本机运行状态中排除 egress_policy 阻塞。"
    />
    <ProblemPanel v-if="error" :error="error" @retry="load" />
    <el-skeleton v-if="loading && !items.length" :rows="6" animated />
    <EmptyState
      v-else-if="!items.length && !error"
      title="当前项目还没有数据源"
      :description="
        canAdmin
          ? '先创建 ACTIVE EndpointPolicy，再添加 MySQL 或 PostgreSQL 数据源。'
          : '请联系 Admin 配置端点、数据源与 SOURCE_USE / TARGET_USE 授权。'
      "
      :action-label="canAdmin ? '新建数据源' : undefined"
      @action="openCreate"
    />

    <section v-else class="content-card">
      <el-table :data="items" row-key="id">
        <el-table-column label="名称" min-width="190">
          <template #default="{ row }">
            <div class="primary-cell">
              <strong>{{ row.name }}</strong>
              <span>{{ row.description || "无说明" }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="引擎" width="150">
          <template #default="{ row }">{{ row.engine === "MYSQL_8" ? "MySQL 8" : "PostgreSQL 15" }}</template>
        </el-table-column>
        <el-table-column label="端点" width="140">
          <template #default="{ row }"><code>{{ row.endpoint_redacted }}</code></template>
        </el-table-column>
        <el-table-column label="凭据" width="120">
          <template #default="{ row }">
            <StateBadge :value="row.credential_status" />
          </template>
        </el-table-column>
        <el-table-column label="最近连接测试" min-width="210">
          <template #default="{ row }">
            <div class="primary-cell">
              <StateBadge :value="testResults[row.id]?.status ?? row.last_test_status ?? '未测试'" />
              <span>{{ formatTime(testResults[row.id]?.tested_at ?? row.last_tested_at) }}</span>
              <code v-if="testResults[row.id]?.error_code ?? row.last_test_error_code">
                {{ testResults[row.id]?.error_code ?? row.last_test_error_code }}
              </code>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }"><StateBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="操作" min-width="520" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="canReadMetadata"
              size="small"
              :disabled="!egressReady"
              @click="openMetadata(row)"
            >
              查看元数据
            </el-button>
            <el-button
              v-if="canAdmin"
              size="small"
              :disabled="!egressReady"
              :loading="testingId === row.id"
              @click="runTest(row)"
            >
              测试连接
            </el-button>
            <el-button v-if="canAdmin" size="small" @click="openDetail(row)">连接详情</el-button>
            <el-button
              v-if="canAdmin"
              size="small"
              :disabled="operationId === row.id"
              @click="openEdit(row)"
            >
              编辑
            </el-button>
            <el-button
              v-if="canAdmin"
              size="small"
              :disabled="operationId === row.id"
              @click="openRotate(row)"
            >
              轮换凭据
            </el-button>
            <el-button
              v-if="canAdmin"
              size="small"
              :loading="operationId === row.id"
              @click="changeStatus(row)"
            >
              {{ row.status === "ACTIVE" ? "停用" : "恢复" }}
            </el-button>
            <el-button
              v-if="canAdmin"
              size="small"
              type="danger"
              plain
              :disabled="operationId === row.id"
              @click="removeDatasource(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="hasMore" class="page-actions">
        <el-button :loading="loadingMore" @click="loadMore">加载下一页</el-button>
      </div>
    </section>

    <el-dialog v-model="createVisible" title="新建数据源" width="min(720px, 96vw)" destroy-on-close>
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <ProblemPanel v-if="policyError" :error="policyError" @retry="loadPolicies" />
      <el-form label-position="top" @submit.prevent="submitCreate">
        <div class="form-grid form-grid--two">
          <el-form-item label="名称" required>
            <el-input v-model="form.name" maxlength="128" />
          </el-form-item>
          <el-form-item label="数据库类型" required>
            <el-select v-model="form.engine" class="full-width" @change="engineChanged">
              <el-option label="MySQL 8" value="MYSQL_8" />
              <el-option label="PostgreSQL 15" value="POSTGRESQL_15" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="EndpointPolicy" required>
          <el-select
            v-model="form.endpointPolicyId"
            class="full-width"
            placeholder="选择 ACTIVE 端点策略"
            :disabled="!createPolicies.length"
          >
            <el-option
              v-for="policy in createPolicies"
              :key="policy.id"
              :label="policy.name"
              :value="policy.id"
            />
          </el-select>
          <span class="field-help">网络准入由服务端和容器出口策略复检，前端选择不能绕过。</span>
        </el-form-item>
        <div class="form-grid form-grid--host">
          <el-form-item label="主机名或 IP" required>
            <el-input v-model="form.host" maxlength="253" placeholder="不含协议、路径或 JDBC 参数" />
          </el-form-item>
          <el-form-item label="端口" required>
            <el-input-number v-model="form.port" :min="1" :max="65535" controls-position="right" />
          </el-form-item>
        </div>
        <div class="form-grid form-grid--two">
          <el-form-item label="数据库" required>
            <el-input v-model="form.databaseName" maxlength="128" />
          </el-form-item>
          <el-form-item label="默认 Schema" required>
            <el-input v-model="form.defaultSchema" maxlength="128" placeholder="PostgreSQL 通常为 public" />
          </el-form-item>
        </div>
        <div class="form-grid form-grid--two">
          <el-form-item label="用户名" required>
            <el-input v-model="form.username" maxlength="128" autocomplete="off" />
          </el-form-item>
          <el-form-item label="密码" required>
            <el-input
              v-model="form.password"
              type="password"
              maxlength="512"
              autocomplete="new-password"
              show-password
            />
          </el-form-item>
        </div>
        <el-form-item label="TLS/SSL 模式" required>
          <el-select v-model="form.sslMode" class="full-width">
            <el-option label="VERIFY_FULL（完整校验）" value="VERIFY_FULL" />
            <el-option label="VERIFY_CA（校验证书）" value="VERIFY_CA" />
            <el-option label="REQUIRE（要求加密）" value="REQUIRE" />
            <el-option label="DISABLE（禁用）" value="DISABLE" />
          </el-select>
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="form.description" type="textarea" maxlength="1000" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :disabled="!canSubmit" :loading="submitting" @click="submitCreate">
          保存数据源
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="编辑数据源" width="min(720px, 96vw)" destroy-on-close>
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <ProblemPanel v-if="policyError" :error="policyError" @retry="loadPolicies" />
      <el-skeleton v-if="editLoading" :rows="10" animated />
      <el-form v-else-if="editOriginal" label-position="top" @submit.prevent="submitEdit">
        <el-alert
          type="warning"
          :closable="false"
          show-icon
          title="连接定位字段不会覆盖历史"
          description="主机、端口、数据库、Schema、用户名、引擎、SSL 或端点策略变化，会先执行真实连接与出口验证，再创建新的不可变修订。凭据请使用独立的“轮换凭据”动作。"
        />
        <div class="form-grid form-grid--two">
          <el-form-item label="名称" required>
            <el-input v-model="editForm.name" maxlength="128" />
          </el-form-item>
          <el-form-item label="数据库类型" required>
            <el-select v-model="editForm.engine" class="full-width" @change="editEngineChanged">
              <el-option label="MySQL 8" value="MYSQL_8" />
              <el-option label="PostgreSQL 15" value="POSTGRESQL_15" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="EndpointPolicy" required>
          <el-select
            v-model="editForm.endpointPolicyId"
            class="full-width"
            placeholder="选择引擎匹配的 ACTIVE 端点策略"
            :disabled="!editPolicies.length"
          >
            <el-option
              v-for="policy in editPolicies"
              :key="policy.id"
              :label="policy.name"
              :value="policy.id"
            />
          </el-select>
        </el-form-item>
        <div class="form-grid form-grid--host">
          <el-form-item label="主机名或 IP" required>
            <el-input
              v-model="editForm.host"
              maxlength="253"
              placeholder="不含协议、路径或 JDBC 参数"
            />
          </el-form-item>
          <el-form-item label="端口" required>
            <el-input-number
              v-model="editForm.port"
              :min="1"
              :max="65535"
              controls-position="right"
            />
          </el-form-item>
        </div>
        <div class="form-grid form-grid--two">
          <el-form-item label="数据库" required>
            <el-input v-model="editForm.databaseName" maxlength="128" />
          </el-form-item>
          <el-form-item label="默认 Schema" required>
            <el-input
              v-model="editForm.defaultSchema"
              maxlength="128"
              placeholder="PostgreSQL 通常为 public"
            />
          </el-form-item>
        </div>
        <div class="form-grid form-grid--two">
          <el-form-item label="用户名" required>
            <el-input v-model="editForm.username" maxlength="128" autocomplete="off" />
          </el-form-item>
          <el-form-item label="TLS/SSL 模式" required>
            <el-select v-model="editForm.sslMode" class="full-width">
              <el-option label="VERIFY_FULL（完整校验）" value="VERIFY_FULL" />
              <el-option label="VERIFY_CA（校验证书）" value="VERIFY_CA" />
              <el-option label="REQUIRE（要求加密）" value="REQUIRE" />
              <el-option label="DISABLE（禁用）" value="DISABLE" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="说明">
          <el-input
            v-model="editForm.description"
            type="textarea"
            maxlength="1000"
            show-word-limit
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button
          type="primary"
          :disabled="!canSubmitEdit"
          :loading="submitting"
          @click="submitEdit"
        >
          验证并保存
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="rotateVisible" title="轮换数据源凭据" width="min(520px, 96vw)" destroy-on-close>
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="旧密码不会显示"
        description="服务端先用新密码完成真实连接、身份与出口验证；全部通过后才新增 secret 并切换，旧 secret 仅保留生命周期与审计记录。"
      />
      <el-form label-position="top" @submit.prevent="submitRotate">
        <el-form-item label="新密码" required>
          <el-input
            v-model="rotatePassword"
            type="password"
            maxlength="512"
            autocomplete="new-password"
            show-password
          />
        </el-form-item>
        <el-form-item label="确认新密码" required>
          <el-input
            v-model="rotateConfirmation"
            type="password"
            maxlength="512"
            autocomplete="new-password"
            show-password
          />
          <span v-if="rotateConfirmation && rotatePassword !== rotateConfirmation" class="field-help">
            两次输入不一致。
          </span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="rotateVisible = false">取消</el-button>
        <el-button
          type="primary"
          :disabled="!canRotate"
          :loading="submitting"
          @click="submitRotate"
        >
          验证并轮换
        </el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="Admin 连接详情" size="min(620px, 94vw)">
      <ProblemPanel v-if="detailError" :error="detailError" :show-retry="false" />
      <el-skeleton v-if="detailLoading" :rows="8" animated />
      <dl v-else-if="detail" class="detail-list">
        <div><dt>名称</dt><dd>{{ detail.name }}</dd></div>
        <div><dt>引擎</dt><dd>{{ detail.engine }}</dd></div>
        <div><dt>主机</dt><dd>{{ detail.current_revision.host }}</dd></div>
        <div><dt>端口</dt><dd>{{ detail.current_revision.port }}</dd></div>
        <div><dt>数据库</dt><dd>{{ detail.current_revision.database_name }}</dd></div>
        <div><dt>默认 Schema</dt><dd>{{ detail.current_revision.default_schema }}</dd></div>
        <div><dt>用户名</dt><dd>{{ detail.current_revision.username }}</dd></div>
        <div><dt>SSL 模式</dt><dd>{{ detail.current_revision.ssl_mode }}</dd></div>
        <div><dt>凭据状态</dt><dd>{{ detail.current_secret.status }}（版本 {{ detail.current_secret.secret_version }}）</dd></div>
        <div><dt>密码</dt><dd>永不回显</dd></div>
      </dl>
    </el-drawer>

    <el-drawer
      v-model="metadataVisible"
      :title="`${metadataDatasource?.name ?? ''} · 表与字段元数据`"
      size="min(840px, 96vw)"
      @closed="closeMetadata"
    >
      <div class="metadata-action">
        <div class="metadata-purpose-copy">
          <strong>按本次用途读取</strong>
          <span>
            服务端会精确校验 SOURCE_USE 或 TARGET_USE；通用数据源页不会替你假定复制方向。
          </span>
        </div>
        <el-radio-group
          :model-value="metadataUsage"
          :disabled="metadataLoading || metadataLoadingMore || metadataLoadingAll"
          @change="(usage: DatasourceUsage) => loadMetadataForUsage(usage)"
        >
          <el-radio-button value="SOURCE_USE">作为复制源</el-radio-button>
          <el-radio-button value="TARGET_USE">作为复制目标</el-radio-button>
        </el-radio-group>
      </div>
      <ProblemPanel v-if="metadataError" :error="metadataError" @retry="retryMetadata" />
      <div v-if="metadataError && metadataRequiresExplicitRetry" class="page-actions">
        <el-button
          type="primary"
          plain
          :disabled="metadataLoading || metadataLoadingMore || metadataLoadingAll"
          @click="retryMetadata"
        >
          重新读取元数据
        </el-button>
      </div>
      <el-skeleton v-if="metadataLoading" :rows="8" animated />
      <el-collapse v-else-if="tables.length">
        <el-collapse-item
          v-for="table in tables"
          :key="`${table.schema_name}.${table.table_name}`"
          :title="`${table.schema_name}.${table.table_name}`"
          :name="`${table.schema_name}.${table.table_name}`"
        >
          <el-table :data="table.columns" size="small">
            <el-table-column prop="ordinal" label="#" width="60" />
            <el-table-column prop="name" label="字段" min-width="160" />
            <el-table-column prop="native_type" label="原生类型" min-width="180" />
            <el-table-column label="可空" width="80">
              <template #default="{ row }">{{ row.nullable ? "是" : "否" }}</template>
            </el-table-column>
            <el-table-column label="主键" width="80">
              <template #default="{ row }">{{ row.primary_key ? "是" : "否" }}</template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
      <EmptyState
        v-else-if="metadataUsage"
        title="未读取到表元数据"
        description="当前用途范围没有表，或服务端尚未返回真实元数据。"
      />
      <EmptyState
        v-else
        title="请选择元数据用途"
        description="只有选择复制源或复制目标后才会发起请求；未获该用途授权时服务端会明确拒绝。"
      />
      <div v-if="tables.length && metadataHasMore" class="page-actions">
        <el-button
          :loading="metadataLoadingMore && !metadataLoadingAll"
          :disabled="metadataLoadingAll"
          @click="loadMetadataPage(true)"
        >
          加载下一页
        </el-button>
        <el-button
          type="primary"
          plain
          :loading="metadataLoadingAll"
          :disabled="metadataLoadingMore && !metadataLoadingAll"
          @click="loadAllMetadata"
        >
          加载全部剩余表
        </el-button>
      </div>
      <el-alert
        v-else-if="tables.length"
        type="success"
        :closable="false"
        :title="`已加载全部 ${tables.length} 张表的真实元数据`"
      />
    </el-drawer>
  </div>
</template>
