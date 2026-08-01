<script setup lang="ts">
import { ElMessage } from "element-plus";
import { computed, reactive, ref, watch } from "vue";

import { newIdempotencyKey } from "../api/client";
import {
  createJob,
  listDatasources,
  listDatasourceTables,
  updateJob,
} from "../api/resources";
import type {
  ColumnSchema,
  DatasourceSummary,
  JobSpec,
  OracleLogicalType,
  SyncJob,
  TableSchema,
} from "../types";

import ProblemPanel from "./ProblemPanel.vue";

const visible = defineModel<boolean>({ required: true });
const props = defineProps<{
  projectId: string;
  job?: SyncJob | null;
}>();
const emit = defineEmits<{ created: []; saved: [] }>();

interface MappingDraft {
  source: ColumnSchema;
  enabled: boolean;
  targetColumn: string;
  compatibility: "" | "EXACT" | "WIDENING";
}

const step = ref(0);
const loading = ref(false);
const submitting = ref(false);
const error = ref<unknown>(null);
const datasources = ref<DatasourceSummary[]>([]);
const sourceTables = ref<TableSchema[]>([]);
const targetTables = ref<TableSchema[]>([]);
const sourceLoading = ref(false);
const targetLoading = ref(false);
const sourceRevisionId = ref("");
const targetRevisionId = ref("");
const mappings = ref<MappingDraft[]>([]);
const createKey = ref(newIdempotencyKey());
const isEditing = computed(() => props.job !== null && props.job !== undefined);

const form = reactive({
  name: "",
  description: "",
  sourceDatasourceId: "",
  sourceTableKey: "",
  targetDatasourceId: "",
  targetTableKey: "",
  channel: 1,
  timeoutMinutes: 60,
});

const sourceDatasource = computed(() =>
  datasources.value.find((item) => item.id === form.sourceDatasourceId),
);
const targetDatasource = computed(() =>
  datasources.value.find((item) => item.id === form.targetDatasourceId),
);
const sourceTable = computed(() =>
  sourceTables.value.find((item) => tableKey(item) === form.sourceTableKey),
);
const targetTable = computed(() =>
  targetTables.value.find((item) => tableKey(item) === form.targetTableKey),
);
const activeDatasources = computed(() =>
  datasources.value.filter(
    (item) => item.status === "ACTIVE" && item.credential_status === "READY",
  ),
);
const selectedMappings = computed(() => mappings.value.filter((mapping) => mapping.enabled));
const duplicateTargets = computed(() => {
  const counts = new Map<string, number>();
  for (const mapping of selectedMappings.value) {
    if (mapping.targetColumn) counts.set(mapping.targetColumn, (counts.get(mapping.targetColumn) ?? 0) + 1);
  }
  return new Set([...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name));
});
const mappingComplete = computed(
  () =>
    selectedMappings.value.length > 0 &&
    selectedMappings.value.every(
      (mapping) => mapping.targetColumn.length > 0 && mapping.compatibility.length > 0,
    ) &&
    selectedMappings.value.every((mapping) => resolveOracleLogicalType(mapping) !== null) &&
    duplicateTargets.value.size === 0,
);
const canNext = computed(() => {
  if (step.value === 0) return form.name.trim().length > 0;
  if (step.value === 1) {
    return Boolean(
      sourceDatasource.value &&
        sourceTable.value?.oracle_compatible,
    );
  }
  if (step.value === 2) {
    return Boolean(
      targetDatasource.value &&
        targetTable.value?.oracle_compatible &&
        targetTable.value.target_insert_compatible &&
        mappingComplete.value,
    );
  }
  if (step.value === 3) {
    return (
      Number.isInteger(form.channel) &&
      form.channel >= 1 &&
      form.channel <= 16 &&
      Number.isInteger(form.timeoutMinutes) &&
      form.timeoutMinutes >= 1 &&
      form.timeoutMinutes <= 10080
    );
  }
  return true;
});

function tableKey(table: TableSchema): string {
  return `${table.schema_name}\u0000${table.table_name}`;
}

function reset(): void {
  step.value = 0;
  error.value = null;
  form.name = "";
  form.description = "";
  form.sourceDatasourceId = "";
  form.sourceTableKey = "";
  form.targetDatasourceId = "";
  form.targetTableKey = "";
  form.channel = 1;
  form.timeoutMinutes = 60;
  sourceTables.value = [];
  targetTables.value = [];
  mappings.value = [];
  sourceRevisionId.value = "";
  targetRevisionId.value = "";
  createKey.value = newIdempotencyKey();
}

async function loadDatasources(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    const collected: DatasourceSummary[] = [];
    let cursor: string | undefined;
    do {
      const page = await listDatasources(
        props.projectId,
        cursor,
        undefined,
        200,
      );
      collected.push(...page.items);
      cursor =
        page.has_more && page.next_cursor
          ? page.next_cursor
          : undefined;
    } while (cursor);
    datasources.value = collected;
  } catch (caught) {
    error.value = caught;
    datasources.value = [];
  } finally {
    loading.value = false;
  }
}

async function sourceChanged(): Promise<void> {
  sourceRevisionId.value =
    sourceDatasource.value?.current_revision_id ?? "";
  targetRevisionId.value = "";
  form.sourceTableKey = "";
  form.targetDatasourceId = "";
  form.targetTableKey = "";
  sourceTables.value = [];
  targetTables.value = [];
  mappings.value = [];
  if (!form.sourceDatasourceId) return;
  sourceLoading.value = true;
  error.value = null;
  try {
    sourceTables.value = await loadAllTables(form.sourceDatasourceId, "SOURCE_USE");
  } catch (caught) {
    error.value = caught;
  } finally {
    sourceLoading.value = false;
  }
}

function sourceTableChanged(): void {
  const table = sourceTable.value;
  mappings.value = (table?.columns ?? []).map((column) => ({
    source: column,
    enabled: column.oracle_supported,
    targetColumn: "",
    compatibility: "",
  }));
  form.targetDatasourceId = "";
  form.targetTableKey = "";
  targetTables.value = [];
}

async function targetChanged(): Promise<void> {
  targetRevisionId.value =
    targetDatasource.value?.current_revision_id ?? "";
  form.targetTableKey = "";
  targetTables.value = [];
  for (const mapping of mappings.value) mapping.targetColumn = "";
  if (!form.targetDatasourceId) return;
  targetLoading.value = true;
  error.value = null;
  try {
    targetTables.value = await loadAllTables(form.targetDatasourceId, "TARGET_USE");
  } catch (caught) {
    error.value = caught;
  } finally {
    targetLoading.value = false;
  }
}

async function loadAllTables(
  datasourceId: string,
  usage: "SOURCE_USE" | "TARGET_USE",
): Promise<TableSchema[]> {
  const collected: TableSchema[] = [];
  let cursor: string | undefined;
  do {
    const page = await listDatasourceTables(datasourceId, { usage, cursor });
    collected.push(...page.items);
    cursor =
      page.has_more && page.next_cursor
        ? page.next_cursor
        : undefined;
  } while (cursor);
  return collected;
}

function targetTableChanged(): void {
  const targetColumns = targetTable.value?.columns ?? [];
  for (const mapping of mappings.value) {
    const target = targetColumns.find(
      (candidate) => candidate.name.toLocaleLowerCase() === mapping.source.name.toLocaleLowerCase(),
    );
    mapping.targetColumn = target?.name ?? "";
    mapping.compatibility =
      target?.native_type.toLocaleLowerCase() === mapping.source.native_type.toLocaleLowerCase()
        ? "EXACT"
        : "";
  }
}

function selectedTargetColumn(mapping: MappingDraft): ColumnSchema | undefined {
  return targetTable.value?.columns.find((column) => column.name === mapping.targetColumn);
}

function targetColumnChanged(mapping: MappingDraft): void {
  const target = selectedTargetColumn(mapping);
  mapping.compatibility =
    target?.native_type.toLocaleLowerCase() === mapping.source.native_type.toLocaleLowerCase()
      ? "EXACT"
      : "";
}

function resolveOracleLogicalType(mapping: MappingDraft): OracleLogicalType | null {
  const target = selectedTargetColumn(mapping);
  const sourceType = mapping.source.logical_type;
  const targetType = target?.logical_type ?? null;
  if (
    !mapping.source.oracle_supported ||
    !target?.oracle_supported ||
    sourceType === null ||
    targetType === null
  ) {
    return null;
  }
  if (sourceType === targetType) return sourceType;
  if (
    mapping.compatibility === "WIDENING" &&
    sourceType === "INTEGER" &&
    targetType === "DECIMAL"
  ) {
    return "DECIMAL";
  }
  return null;
}

function buildSpec(): JobSpec {
  const source = sourceDatasource.value;
  const target = targetDatasource.value;
  const sourceTableValue = sourceTable.value;
  const targetTableValue = targetTable.value;
  if (!source || !target || !sourceTableValue || !targetTableValue || !mappingComplete.value) {
    throw new Error("任务表单尚未完成。");
  }
  return {
    schema_version: "1.0",
    source: {
      datasource_id: source.id,
      datasource_revision_id: sourceRevisionId.value,
      plugin_name: source.engine === "MYSQL_8" ? "mysqlreader" : "postgresqlreader",
      table: {
        schema_name: sourceTableValue.schema_name,
        table_name: sourceTableValue.table_name,
      },
    },
    target: {
      datasource_id: target.id,
      datasource_revision_id: targetRevisionId.value,
      plugin_name: target.engine === "MYSQL_8" ? "mysqlwriter" : "postgresqlwriter",
      table: {
        schema_name: targetTableValue.schema_name,
        table_name: targetTableValue.table_name,
      },
    },
    selection_mode:
      selectedMappings.value.length === mappings.value.length ? "ALL_COLUMNS" : "SELECTED_COLUMNS",
    mappings: selectedMappings.value.map((mapping) => {
      const targetColumn = selectedTargetColumn(mapping);
      if (!targetColumn) throw new Error(`目标字段 ${mapping.targetColumn} 不存在。`);
      if (!mapping.compatibility) {
        throw new Error(`字段 ${mapping.source.name} 尚未声明映射兼容性。`);
      }
      const oracleLogicalType = resolveOracleLogicalType(mapping);
      if (oracleLogicalType === null) {
        throw new Error(`字段 ${mapping.source.name} 无法按 V1 oracle 规则无损核验。`);
      }
      return {
        source_column: mapping.source.name,
        source_ordinal: mapping.source.ordinal,
        source_type: mapping.source.native_type,
        source_nullable: mapping.source.nullable,
        target_column: targetColumn.name,
        target_ordinal: targetColumn.ordinal,
        target_type: targetColumn.native_type,
        target_nullable: targetColumn.nullable,
        oracle_logical_type: oracleLogicalType,
        compatibility: mapping.compatibility,
      };
    }),
    source_consistency_mode: "OPERATOR_QUIESCED",
    target_precondition: "EMPTY_AND_VERIFIABLE",
    write_semantics: "INSERT_ONLY_ONCE",
    duplicate_policy: "REJECT_NONEMPTY_TARGET",
    partial_write_policy: "MANUAL_REMEDIATE",
    write_policy: {
      mode: "INSERT",
      target_table_must_exist: true,
      target_table_must_be_empty: true,
      platform_may_mutate_target_before_run: false,
    },
    execution_policy: {
      channel: form.channel,
      timeout_seconds: form.timeoutMinutes * 60,
      dirty_data_limit: {
        record_count: 0,
        percentage: 0,
      },
    },
  };
}

async function submit(): Promise<void> {
  submitting.value = true;
  error.value = null;
  try {
    const payload = {
      name: form.name.trim(),
      description: form.description.trim() || null,
      draft_spec: buildSpec(),
    };
    if (props.job) {
      await updateJob(props.job, payload);
    } else {
      await createJob(
        props.projectId,
        payload,
        createKey.value,
      );
    }
    visible.value = false;
    ElMessage.success(
      props.job
        ? "新草稿已保存；历史发布版本未改变，当前草稿需要重新校验。"
        : "任务草稿已保存，尚未校验。",
    );
    if (!props.job) emit("created");
    emit("saved");
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
  }
}

async function initialize(): Promise<void> {
  reset();
  await loadDatasources();
  const job = props.job;
  if (!job) return;
  form.name = job.name;
  form.description = job.description ?? "";
  form.channel = job.draft_spec.execution_policy.channel;
  form.timeoutMinutes =
    job.draft_spec.execution_policy.timeout_seconds / 60;
  form.sourceDatasourceId = job.draft_spec.source.datasource_id;
  const currentSource = sourceDatasource.value;
  if (
    !currentSource ||
    currentSource.current_revision_id !==
      job.draft_spec.source.datasource_revision_id
  ) {
    throw new Error(
      "草稿绑定的 Reader 连接修订已不是当前修订。编辑器不会用新连接信息静默替换历史绑定；请先核对数据源修订后再创建明确的新草稿。",
    );
  }
  await sourceChanged();
  sourceRevisionId.value =
    job.draft_spec.source.datasource_revision_id;
  form.sourceTableKey = `${job.draft_spec.source.table.schema_name}\u0000${job.draft_spec.source.table.table_name}`;
  if (!sourceTable.value) {
    throw new Error(
      "当前源表已不在真实元数据结果中，不能静默伪造编辑器内容；请恢复元数据可见性后重试。",
    );
  }
  sourceTableChanged();
  form.targetDatasourceId = job.draft_spec.target.datasource_id;
  const currentTarget = targetDatasource.value;
  if (
    !currentTarget ||
    currentTarget.current_revision_id !==
      job.draft_spec.target.datasource_revision_id
  ) {
    throw new Error(
      "草稿绑定的 Writer 连接修订已不是当前修订。编辑器不会用新连接信息静默替换历史绑定；请先核对数据源修订后再创建明确的新草稿。",
    );
  }
  await targetChanged();
  targetRevisionId.value =
    job.draft_spec.target.datasource_revision_id;
  form.targetTableKey = `${job.draft_spec.target.table.schema_name}\u0000${job.draft_spec.target.table.table_name}`;
  if (!targetTable.value) {
    throw new Error(
      "当前目标表已不在真实元数据结果中，不能静默伪造编辑器内容；请恢复元数据可见性后重试。",
    );
  }
  targetTableChanged();
  const existing = new Map(
    job.draft_spec.mappings.map((mapping) => [
      mapping.source_column,
      mapping,
    ]),
  );
  for (const mapping of mappings.value) {
    const saved = existing.get(mapping.source.name);
    mapping.enabled = saved !== undefined;
    mapping.targetColumn = saved?.target_column ?? "";
    mapping.compatibility = saved?.compatibility ?? "";
  }
}

watch(visible, (isVisible) => {
  if (isVisible) {
    void initialize().catch((caught: unknown) => {
      error.value = caught;
    });
  }
});
</script>

<template>
  <el-dialog
    v-model="visible"
    :title="isEditing ? '编辑任务并保存新草稿' : '新建一次性复制任务'"
    width="min(1080px, 98vw)"
    destroy-on-close
    class="job-wizard-dialog"
  >
    <el-alert
      v-if="isEditing && props.job?.latest_published_version_id"
      type="info"
      :closable="false"
      show-icon
      title="历史版本保持不可变"
      description="保存会更新当前草稿并回到 DRAFT；已发布 JobVersion 仍可只读查看，绝不会被覆盖。"
    />
    <el-alert
      type="warning"
      :closable="false"
      show-icon
      title="一次性离线全量复制"
      description="源表从运行前检查到独立核验完成必须保持静默；目标表需预创建、为空且可核验。平台不会创建、清空或修改业务表。"
    />
    <ProblemPanel v-if="error" :error="error" :show-retry="false" />
    <el-steps :active="step" finish-status="success" align-center class="wizard-steps">
      <el-step title="基本信息" />
      <el-step title="Reader" />
      <el-step title="Writer 与映射" />
      <el-step title="运行参数" />
      <el-step title="确认保存" />
    </el-steps>

    <el-skeleton v-if="loading" :rows="6" animated />
    <section v-else class="wizard-body">
      <el-form v-if="step === 0" label-position="top">
        <el-form-item label="任务名称" required>
          <el-input v-model="form.name" maxlength="128" />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="form.description" type="textarea" maxlength="1000" show-word-limit />
        </el-form-item>
      </el-form>

      <div v-else-if="step === 1" class="wizard-section">
        <el-form label-position="top">
          <el-form-item label="Reader 数据源" required>
            <el-select
              v-model="form.sourceDatasourceId"
              class="full-width"
              placeholder="选择具备 SOURCE_USE 的真实数据源"
              @change="sourceChanged"
            >
              <el-option
                v-for="source in activeDatasources"
                :key="source.id"
                :label="`${source.name} · ${source.engine}`"
                :value="source.id"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="源表" required>
            <el-select
              v-model="form.sourceTableKey"
              class="full-width"
              placeholder="从真实元数据中选择"
              :loading="sourceLoading"
              :disabled="!form.sourceDatasourceId"
              filterable
              @change="sourceTableChanged"
            >
              <el-option
                v-for="table in sourceTables"
                :key="tableKey(table)"
                :label="`${table.schema_name}.${table.table_name}`"
                :value="tableKey(table)"
              />
            </el-select>
          </el-form-item>
        </el-form>
        <el-alert
          type="info"
          :closable="false"
          title="源表静默责任"
          description="本向导不会用复选框伪装数据库快照。真正执行前，Operator 必须重新提交全窗口静默确认。"
        />
      </div>

      <div v-else-if="step === 2" class="wizard-section">
        <div class="form-grid form-grid--two">
          <el-form-item label="Writer 数据源" required>
            <el-select
              v-model="form.targetDatasourceId"
              class="full-width"
              placeholder="选择具备 TARGET_USE 和 ACTIVE TransferPolicy 的数据源"
              @change="targetChanged"
            >
              <el-option
                v-for="target in activeDatasources.filter((item) => item.id !== form.sourceDatasourceId)"
                :key="target.id"
                :label="`${target.name} · ${target.engine}`"
                :value="target.id"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="目标表" required>
            <el-select
              v-model="form.targetTableKey"
              class="full-width"
              placeholder="选择预创建的真实目标表"
              :loading="targetLoading"
              :disabled="!form.targetDatasourceId"
              filterable
              @change="targetTableChanged"
            >
              <el-option
                v-for="table in targetTables"
                :key="tableKey(table)"
                :label="`${table.schema_name}.${table.table_name}`"
                :value="tableKey(table)"
              />
            </el-select>
          </el-form-item>
        </div>

        <el-table v-if="mappings.length" :data="mappings" row-key="source.name" max-height="380">
          <el-table-column label="复制" width="72">
            <template #default="{ row }">
              <el-checkbox v-model="row.enabled" :aria-label="`复制源字段 ${row.source.name}`" />
            </template>
          </el-table-column>
          <el-table-column label="源字段" min-width="210">
            <template #default="{ row }">
              <div class="primary-cell">
                <strong>{{ row.source.name }}</strong>
                <span>{{ row.source.native_type }} · {{ row.source.nullable ? "可空" : "非空" }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="目标字段" min-width="240">
            <template #default="{ row }">
              <el-select
                v-model="row.targetColumn"
                filterable
                :disabled="!row.enabled || !targetTable"
                placeholder="选择一对一目标字段"
                :class="{ 'is-duplicate': duplicateTargets.has(row.targetColumn) }"
                @change="targetColumnChanged(row)"
              >
                <el-option
                  v-for="column in targetTable?.columns ?? []"
                  :key="column.name"
                  :label="`${column.name} · ${column.native_type}`"
                  :value="column.name"
                />
              </el-select>
            </template>
          </el-table-column>
          <el-table-column label="映射声明" min-width="190">
            <template #default="{ row }">
              <el-select
                v-model="row.compatibility"
                :disabled="!row.enabled"
                placeholder="请选择，服务端复核"
              >
                <el-option label="精确映射" value="EXACT" />
                <el-option label="安全扩宽" value="WIDENING" />
              </el-select>
            </template>
          </el-table-column>
        </el-table>
        <p v-if="duplicateTargets.size" class="field-error">
          目标字段不能重复映射：{{ [...duplicateTargets].join("、") }}
        </p>
        <p class="field-help">
          同名推荐和兼容声明只用于构造草稿；真实类型兼容性、TransferPolicy 范围和目标可核验能力以服务端校验为准。
        </p>
      </div>

      <el-form v-else-if="step === 3" label-position="top">
        <div class="form-grid form-grid--two">
          <el-form-item label="Channel" required>
            <el-input-number v-model="form.channel" :min="1" :max="16" />
          </el-form-item>
          <el-form-item label="执行超时（分钟）" required>
            <el-input-number v-model="form.timeoutMinutes" :min="1" :max="10080" />
          </el-form-item>
        </div>
        <dl class="policy-list">
          <div><dt>读取范围</dt><dd>静默源表全部行</dd></div>
          <div><dt>写入方式</dt><dd>insert-only，一次性执行</dd></div>
          <div><dt>目标前提</dt><dd>预创建、可核验，Worker 启动前实测为空</dd></div>
          <div><dt>脏数据容忍</dt><dd>0 条 / 0%（不可修改）</dd></div>
          <div><dt>失败策略</dt><dd>人工处置 + 独立 RecoveryProbe，绝不自动重试</dd></div>
        </dl>
      </el-form>

      <div v-else class="wizard-section">
        <section class="summary-card">
          <div><span>任务</span><strong>{{ form.name }}</strong></div>
          <div>
            <span>Reader</span>
            <strong>{{ sourceDatasource?.name }} · {{ sourceTable?.schema_name }}.{{ sourceTable?.table_name }}</strong>
          </div>
          <div>
            <span>Writer</span>
            <strong>{{ targetDatasource?.name }} · {{ targetTable?.schema_name }}.{{ targetTable?.table_name }}</strong>
          </div>
          <div><span>字段映射</span><strong>{{ selectedMappings.length }} 个</strong></div>
          <div><span>Channel / 超时</span><strong>{{ form.channel }} / {{ form.timeoutMinutes }} 分钟</strong></div>
        </section>
        <el-alert
          type="warning"
          :closable="false"
          show-icon
          title="保存的是草稿，不是可执行版本"
          description="保存后还必须由服务端校验方向授权、TransferPolicy、Schema 和类型，再由 Developer 发布不可变版本。"
        />
      </div>
    </section>

    <template #footer>
      <div class="form-actions form-actions--spread">
        <el-button @click="visible = false">取消</el-button>
        <div class="inline-actions">
          <el-button v-if="step > 0" @click="step -= 1">上一步</el-button>
          <el-button v-if="step < 4" type="primary" :disabled="!canNext" @click="step += 1">
            下一步
          </el-button>
          <el-button v-else type="primary" :loading="submitting" @click="submit">
            {{ isEditing ? "保存新草稿" : "保存任务草稿" }}
          </el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>
