<script setup lang="ts">
import { ElMessage, ElMessageBox } from "element-plus";
import {
  computed,
  onMounted,
  reactive,
  ref,
  watch,
} from "vue";

import { newIdempotencyKey } from "../api/client";
import {
  createTransferPolicy,
  decideTransferPolicy,
  getDatasourceAdminDetail,
  listDatasourceTables,
  listDatasources,
  listDatasourceUsageGrants,
  listProjectAuditEvents,
  listProjectMembers,
  listTransferPolicies,
  listUsers,
  replaceDatasourceUsageGrants,
  replaceProjectMemberRoles,
  submitTransferPolicy,
  updateTransferPolicy,
} from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import { useAuth } from "../state/auth";
import type {
  AuditEvent,
  DatasourceAdminDetail,
  DatasourceSummary,
  DatasourceUsage,
  DatasourceUsageGrant,
  HealthResponse,
  Project,
  ProjectMember,
  ProjectRole,
  TableSchema,
  TransferPolicy,
  TransferPolicyClassification,
  TransferPolicyDecision,
  TransferPolicyScopeInput,
  User,
} from "../types";

const props = defineProps<{
  project: Project;
  canAdmin: boolean;
  health: HealthResponse | null;
}>();

const auth = useAuth();
const activeTab = ref(props.canAdmin ? "members" : "policies");

const members = ref<ProjectMember[]>([]);
const users = ref<User[]>([]);
const membersLoading = ref(false);
const membersError = ref<unknown>(null);
const memberSavingId = ref<string | null>(null);
const memberRoleDrafts = reactive<Record<string, ProjectRole[]>>({});

const datasources = ref<DatasourceSummary[]>([]);
const grantsByDatasource = reactive<Record<string, DatasourceUsageGrant[]>>({});
const grantDrafts = reactive<Record<string, DatasourceUsage[]>>({});
const grantsLoading = ref(false);
const grantsError = ref<unknown>(null);
const grantSavingKey = ref<string | null>(null);

const policies = ref<TransferPolicy[]>([]);
const policiesLoading = ref(false);
const policiesError = ref<unknown>(null);
const policyActionId = ref<string | null>(null);
const policyDialogVisible = ref(false);
const policySubmitting = ref(false);
const policyError = ref<unknown>(null);
const editingPolicy = ref<TransferPolicy | null>(null);
const createPolicyKey = ref(newIdempotencyKey());
const metadataLoading = ref(false);
const metadataError = ref<unknown>(null);
const metadataIncomplete = ref(false);
const sourceDetail = ref<DatasourceAdminDetail | null>(null);
const targetDetail = ref<DatasourceAdminDetail | null>(null);
const sourceTables = ref<TableSchema[]>([]);
const targetTables = ref<TableSchema[]>([]);
const policyForm = reactive({
  sourceDatasourceId: "",
  targetDatasourceId: "",
  sourceTableKey: "",
  targetTableKey: "",
  sourceSelectionMode: "ALL_COLUMNS" as "ALL_COLUMNS" | "SELECTED_COLUMNS",
  targetSelectionMode: "ALL_COLUMNS" as "ALL_COLUMNS" | "SELECTED_COLUMNS",
  sourceColumns: [] as string[],
  targetColumns: [] as string[],
  classification: "STANDARD" as TransferPolicyClassification,
});
const detailsVisible = ref(false);
const detailPolicy = ref<TransferPolicy | null>(null);
const decisionVisible = ref(false);
const decisionPolicy = ref<TransferPolicy | null>(null);
const decisionForm = reactive({
  decision: "APPROVED" as TransferPolicyDecision,
  comment: "",
  key: newIdempotencyKey(),
});

const auditItems = ref<AuditEvent[]>([]);
const auditLoading = ref(false);
const auditError = ref<unknown>(null);
const auditNextCursor = ref<string | null>(null);
const auditHasMore = ref(false);
const auditFilters = reactive({
  action: "",
  outcome: "" as "" | AuditEvent["outcome"],
});

const egressReady = computed(
  () => props.health?.components.egress_policy?.status === "UP",
);
const workerReady = computed(
  () => {
    const required = [
      "worker",
      "runtime",
      "oracle",
      "lifecycle",
      "dispatcher",
      "reconciler",
      "worker_fencing",
      "workspace_volume",
      "keyrings",
      "audit_chain",
    ];
    return (
      props.health?.status === "UP" &&
      required.every(
        (component) =>
          props.health?.components[component]?.status === "UP",
      )
    );
  },
);
const activeDatasources = computed(() =>
  datasources.value.filter(
    (datasource) =>
      datasource.status === "ACTIVE" &&
      datasource.credential_status === "READY",
  ),
);
const memberRows = computed(() => {
  const byUser = new Map(members.value.map((member) => [member.user.id, member]));
  return users.value
    .filter((user) => user.status === "ACTIVE")
    .map((user) => ({
      user,
      member: byUser.get(user.id) ?? null,
      inheritedAdmin: user.role_assignments.some(
        (assignment) =>
          assignment.scope_type === "ORGANIZATION" &&
          assignment.roles.includes("ADMIN"),
      ),
    }));
});
const grantableMembers = computed(() =>
  members.value.filter((member) =>
    member.roles.some((role) =>
      ["DEVELOPER", "OPERATOR", "VIEWER"].includes(role),
    ),
  ),
);
const selectedSourceTable = computed(() =>
  sourceTables.value.find(
    (table) => tableKey(table) === policyForm.sourceTableKey,
  ),
);
const selectedTargetTable = computed(() =>
  targetTables.value.find(
    (table) => tableKey(table) === policyForm.targetTableKey,
  ),
);
const sourceColumns = computed(
  () => selectedSourceTable.value?.columns ?? [],
);
const targetColumns = computed(
  () => selectedTargetTable.value?.columns ?? [],
);
const sourceSelectedColumns = computed(() =>
  policyForm.sourceSelectionMode === "ALL_COLUMNS"
    ? sourceColumns.value.map((column) => column.name)
    : policyForm.sourceColumns,
);
const targetSelectedColumns = computed(() =>
  policyForm.targetSelectionMode === "ALL_COLUMNS"
    ? targetColumns.value.map((column) => column.name)
    : policyForm.targetColumns,
);
const scopeCompatible = computed(
  () =>
    selectedSourceTable.value?.oracle_compatible === true &&
    selectedTargetTable.value?.oracle_compatible === true &&
    selectedTargetTable.value?.target_insert_compatible === true &&
    selectedSourceTable.value.physical_table_identity_hash !==
      selectedTargetTable.value.physical_table_identity_hash,
);
const canSavePolicy = computed(
  () =>
    egressReady.value &&
    !metadataLoading.value &&
    !metadataIncomplete.value &&
    sourceDetail.value !== null &&
    targetDetail.value !== null &&
    selectedSourceTable.value !== undefined &&
    selectedTargetTable.value !== undefined &&
    sourceSelectedColumns.value.length > 0 &&
    targetSelectedColumns.value.length > 0 &&
    scopeCompatible.value,
);

async function loadMembers(): Promise<void> {
  if (!props.canAdmin) return;
  membersLoading.value = true;
  membersError.value = null;
  try {
    const [memberPage, allUsers] = await Promise.all([
      listProjectMembers(props.project.id),
      loadAllUsers(),
    ]);
    members.value = memberPage.items;
    users.value = allUsers;
    syncMemberDrafts();
  } catch (caught) {
    membersError.value = caught;
    members.value = [];
    users.value = [];
  } finally {
    membersLoading.value = false;
  }
}

async function loadAllUsers(): Promise<User[]> {
  const collected: User[] = [];
  let cursor: string | undefined;
  do {
    const page = await listUsers(cursor);
    collected.push(...page.items);
    cursor = page.has_more && page.next_cursor ? page.next_cursor : undefined;
  } while (cursor);
  return collected;
}

function syncMemberDrafts(): void {
  const roleMap = new Map(
    members.value.map((member) => [
      member.user.id,
      member.roles.filter(isProjectRole),
    ]),
  );
  for (const user of users.value) {
    memberRoleDrafts[user.id] = [...(roleMap.get(user.id) ?? [])];
  }
}

async function saveMemberRoles(user: User): Promise<void> {
  memberSavingId.value = user.id;
  membersError.value = null;
  try {
    const currentMember = members.value.find(
      (member) => member.user.id === user.id,
    );
    if (
      currentMember &&
      (memberRoleDrafts[user.id] ?? []).length === 0
    ) {
      await loadGrants();
      if (grantsError.value) {
        throw new Error(
          "无法核对该成员的数据源用途授权，已安全阻止撤销全部项目角色。请先恢复授权列表读取。",
        );
      }
      const activeDatasourceIds = datasources.value
        .filter((datasource) =>
          (grantsByDatasource[datasource.id] ?? []).some(
            (grant) =>
              grant.organization_member_id ===
                currentMember.organization_member_id &&
              grant.status === "ACTIVE",
          ),
        )
        .map((datasource) => datasource.id);
      if (activeDatasourceIds.length) {
        try {
          await ElMessageBox.confirm(
            `该成员仍有 ${activeDatasourceIds.length} 个数据源用途授权。系统会先安全撤销用途，再撤销项目角色。`,
            "撤销全部项目角色",
            {
              confirmButtonText: "先撤销用途并继续",
              cancelButtonText: "取消",
              type: "warning",
            },
          );
        } catch {
          return;
        }
        for (const datasourceId of activeDatasourceIds) {
          await replaceDatasourceUsageGrants(
            datasourceId,
            currentMember.organization_member_id,
            [],
          );
        }
      }
    }
    await replaceProjectMemberRoles(
      props.project.id,
      user.id,
      memberRoleDrafts[user.id] ?? [],
    );
    ElMessage.success(
      memberRoleDrafts[user.id]?.length
        ? "项目角色已按当前选择原子替换。"
        : "该用户的全部项目角色已撤销。",
    );
    await loadMembers();
    await loadGrants();
  } catch (caught) {
    membersError.value = caught;
  } finally {
    memberSavingId.value = null;
  }
}

async function loadGrants(): Promise<void> {
  if (!props.canAdmin) return;
  grantsLoading.value = true;
  grantsError.value = null;
  try {
    const datasourcePage = await listDatasources(props.project.id);
    datasources.value = datasourcePage.items;
    const pages = await Promise.all(
      datasources.value.map(async (datasource) => ({
        datasource,
        page: await listDatasourceUsageGrants(datasource.id),
      })),
    );
    for (const { datasource, page } of pages) {
      grantsByDatasource[datasource.id] = page.items;
    }
    syncGrantDrafts();
  } catch (caught) {
    grantsError.value = caught;
    datasources.value = [];
  } finally {
    grantsLoading.value = false;
  }
}

function syncGrantDrafts(): void {
  for (const datasource of datasources.value) {
    for (const member of grantableMembers.value) {
      const active = (grantsByDatasource[datasource.id] ?? [])
        .filter(
          (grant) =>
            grant.organization_member_id ===
              member.organization_member_id && grant.status === "ACTIVE",
        )
        .map((grant) => grant.usage);
      grantDrafts[grantKey(datasource.id, member.organization_member_id)] = [
        ...new Set(active),
      ];
    }
  }
}

async function saveGrant(
  datasource: DatasourceSummary,
  member: ProjectMember,
): Promise<void> {
  const key = grantKey(datasource.id, member.organization_member_id);
  grantSavingKey.value = key;
  grantsError.value = null;
  try {
    await replaceDatasourceUsageGrants(
      datasource.id,
      member.organization_member_id,
      grantDrafts[key] ?? [],
    );
    ElMessage.success(
      grantDrafts[key]?.length
        ? "数据源用途授权已更新。"
        : "该成员在此数据源上的用途授权已全部撤销。",
    );
    await loadGrants();
  } catch (caught) {
    grantsError.value = caught;
  } finally {
    grantSavingKey.value = null;
  }
}

async function loadPolicies(): Promise<void> {
  policiesLoading.value = true;
  policiesError.value = null;
  try {
    policies.value = (
      await listTransferPolicies(props.project.id)
    ).items;
  } catch (caught) {
    policiesError.value = caught;
    policies.value = [];
  } finally {
    policiesLoading.value = false;
  }
}

async function ensureDatasources(): Promise<void> {
  if (datasources.value.length) return;
  datasources.value = (
    await listDatasources(props.project.id)
  ).items;
}

async function openCreatePolicy(): Promise<void> {
  policyError.value = null;
  metadataError.value = null;
  if (!egressReady.value) {
    ElMessage.error(
      "出口策略未验证，服务端无法读取真实元数据；已阻止创建空壳策略。",
    );
    return;
  }
  try {
    await ensureDatasources();
  } catch (caught) {
    policiesError.value = caught;
    return;
  }
  editingPolicy.value = null;
  resetPolicyForm();
  createPolicyKey.value = newIdempotencyKey();
  policyDialogVisible.value = true;
}

async function openEditPolicy(policy: TransferPolicy): Promise<void> {
  if (policy.status !== "DRAFT") return;
  if (!egressReady.value) {
    ElMessage.error(
      "出口策略未验证，无法重新读取真实元数据并安全修订范围。",
    );
    return;
  }
  policyError.value = null;
  metadataError.value = null;
  try {
    await ensureDatasources();
    editingPolicy.value = policy;
    resetPolicyForm();
    policyForm.classification = policy.classification;
    policyForm.sourceDatasourceId =
      datasources.value.find(
        (item) =>
          item.current_revision_id ===
          policy.source_datasource_revision_id,
      )?.id ?? "";
    policyForm.targetDatasourceId =
      datasources.value.find(
        (item) =>
          item.current_revision_id ===
          policy.target_datasource_revision_id,
      )?.id ?? "";
    if (
      !policyForm.sourceDatasourceId ||
      !policyForm.targetDatasourceId
    ) {
      throw new Error(
        "当前数据源列表无法解析策略固定的修订，不能在浏览器中安全编辑。",
      );
    }
    policyDialogVisible.value = true;
    await loadPolicyMetadata();
    if (!sourceDetail.value || !targetDetail.value) return;
    hydratePolicyScope(policy);
  } catch (caught) {
    policyError.value = caught;
  }
}

function resetPolicyForm(): void {
  policyForm.sourceDatasourceId = "";
  policyForm.targetDatasourceId = "";
  policyForm.sourceTableKey = "";
  policyForm.targetTableKey = "";
  policyForm.sourceSelectionMode = "ALL_COLUMNS";
  policyForm.targetSelectionMode = "ALL_COLUMNS";
  policyForm.sourceColumns = [];
  policyForm.targetColumns = [];
  policyForm.classification = "STANDARD";
  sourceDetail.value = null;
  targetDetail.value = null;
  sourceTables.value = [];
  targetTables.value = [];
  metadataIncomplete.value = false;
}

async function loadPolicyMetadata(): Promise<void> {
  if (
    !policyForm.sourceDatasourceId ||
    !policyForm.targetDatasourceId ||
    !egressReady.value
  ) {
    return;
  }
  metadataLoading.value = true;
  metadataError.value = null;
  metadataIncomplete.value = false;
  try {
    const [
      loadedSourceDetail,
      loadedTargetDetail,
      sourcePage,
      targetPage,
    ] = await Promise.all([
      getDatasourceAdminDetail(policyForm.sourceDatasourceId),
      getDatasourceAdminDetail(policyForm.targetDatasourceId),
      listDatasourceTables(policyForm.sourceDatasourceId, { usage: "SOURCE_USE" }),
      listDatasourceTables(policyForm.targetDatasourceId, { usage: "TARGET_USE" }),
    ]);
    sourceDetail.value = loadedSourceDetail;
    targetDetail.value = loadedTargetDetail;
    sourceTables.value = sourcePage.items;
    targetTables.value = targetPage.items;
    metadataIncomplete.value =
      sourcePage.has_more || targetPage.has_more;
    policyForm.sourceTableKey = "";
    policyForm.targetTableKey = "";
    policyForm.sourceColumns = [];
    policyForm.targetColumns = [];
  } catch (caught) {
    metadataError.value = caught;
    sourceDetail.value = null;
    targetDetail.value = null;
    sourceTables.value = [];
    targetTables.value = [];
  } finally {
    metadataLoading.value = false;
  }
}

function hydratePolicyScope(policy: TransferPolicy): void {
  const source = sourceTables.value.find(
    (table) =>
      table.table_name === policy.scope_json.source.table &&
      normalizedSchema(sourceDetail.value, table) ===
        policy.scope_json.source.schema,
  );
  const target = targetTables.value.find(
    (table) =>
      table.table_name === policy.scope_json.target.table &&
      normalizedSchema(targetDetail.value, table) ===
        policy.scope_json.target.schema,
  );
  if (!source || !target) {
    metadataError.value = new Error(
      "真实元数据已不再包含策略中的表；不能静默替换为其他表。",
    );
    return;
  }
  policyForm.sourceTableKey = tableKey(source);
  policyForm.targetTableKey = tableKey(target);
  policyForm.sourceSelectionMode = "SELECTED_COLUMNS";
  policyForm.targetSelectionMode = "SELECTED_COLUMNS";
  policyForm.sourceColumns = [...policy.scope_json.source.allowed_columns];
  policyForm.targetColumns = [...policy.scope_json.target.allowed_columns];
}

function sourceTableChanged(): void {
  policyForm.sourceColumns =
    policyForm.sourceSelectionMode === "ALL_COLUMNS"
      ? sourceColumns.value.map((column) => column.name)
      : [];
}

function targetTableChanged(): void {
  policyForm.targetColumns =
    policyForm.targetSelectionMode === "ALL_COLUMNS"
      ? targetColumns.value.map((column) => column.name)
      : [];
}

function sourceModeChanged(): void {
  policyForm.sourceColumns =
    policyForm.sourceSelectionMode === "ALL_COLUMNS"
      ? sourceColumns.value.map((column) => column.name)
      : [];
}

function targetModeChanged(): void {
  policyForm.targetColumns =
    policyForm.targetSelectionMode === "ALL_COLUMNS"
      ? targetColumns.value.map((column) => column.name)
      : [];
}

async function savePolicy(): Promise<void> {
  if (!canSavePolicy.value) return;
  const scope = buildRequestedScope();
  if (!scope || !sourceDetail.value || !targetDetail.value) return;
  policySubmitting.value = true;
  policyError.value = null;
  try {
    if (editingPolicy.value) {
      await updateTransferPolicy(editingPolicy.value, {
        source_datasource_revision_id:
          sourceDetail.value.current_revision.id,
        target_datasource_revision_id:
          targetDetail.value.current_revision.id,
        requested_scope: scope,
        classification: policyForm.classification,
      });
      ElMessage.success(
        "草稿范围已由服务端重新探测、固定并计算新哈希；旧审批已失效。",
      );
    } else {
      await createTransferPolicy(
        props.project.id,
        {
          source_datasource_revision_id:
            sourceDetail.value.current_revision.id,
          target_datasource_revision_id:
            targetDetail.value.current_revision.id,
          requested_scope: scope,
          classification: policyForm.classification,
        },
        createPolicyKey.value,
      );
      ElMessage.success(
        "传输策略草稿已创建；范围哈希来自服务端真实元数据。",
      );
    }
    policyDialogVisible.value = false;
    await loadPolicies();
  } catch (caught) {
    policyError.value = caught;
  } finally {
    policySubmitting.value = false;
  }
}

function buildRequestedScope(): TransferPolicyScopeInput | null {
  if (
    !sourceDetail.value ||
    !targetDetail.value ||
    !selectedSourceTable.value ||
    !selectedTargetTable.value
  ) {
    return null;
  }
  return {
    schema_version: "1.0",
    source: {
      catalog:
        sourceDetail.value.current_revision.database_name,
      schema: normalizedSchema(
        sourceDetail.value,
        selectedSourceTable.value,
      ),
      table: selectedSourceTable.value.table_name,
      selection_mode: policyForm.sourceSelectionMode,
      allowed_columns: [...sourceSelectedColumns.value],
    },
    target: {
      catalog:
        targetDetail.value.current_revision.database_name,
      schema: normalizedSchema(
        targetDetail.value,
        selectedTargetTable.value,
      ),
      table: selectedTargetTable.value.table_name,
      selection_mode: policyForm.targetSelectionMode,
      allowed_columns: [...targetSelectedColumns.value],
    },
  };
}

async function submitPolicy(policy: TransferPolicy): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `将固定当前范围哈希 ${policy.scope_hash.slice(0, 12)}… 并进入审批。`,
      "提交传输策略",
      {
        confirmButtonText: "确认提交",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  policyActionId.value = policy.id;
  policiesError.value = null;
  try {
    await submitTransferPolicy(policy);
    ElMessage.success("策略已进入待审批状态。");
    await loadPolicies();
  } catch (caught) {
    policiesError.value = caught;
  } finally {
    policyActionId.value = null;
  }
}

function openDecision(
  policy: TransferPolicy,
  decision: TransferPolicyDecision,
): void {
  decisionPolicy.value = policy;
  decisionForm.decision = decision;
  decisionForm.comment = "";
  decisionForm.key = newIdempotencyKey();
  policyError.value = null;
  decisionVisible.value = true;
}

async function saveDecision(): Promise<void> {
  if (!decisionPolicy.value) return;
  policySubmitting.value = true;
  policyError.value = null;
  try {
    await decideTransferPolicy(
      decisionPolicy.value,
      {
        decision: decisionForm.decision,
        comment: decisionForm.comment.trim() || null,
      },
      decisionForm.key,
    );
    ElMessage.success(
      decisionForm.decision === "REJECTED"
        ? "策略已立即拒绝。"
        : "审批已记录；达到独立 Admin 门槛后才会生效。",
    );
    decisionVisible.value = false;
    await loadPolicies();
  } catch (caught) {
    policyError.value = caught;
  } finally {
    policySubmitting.value = false;
  }
}

async function revokePolicy(policy: TransferPolicy): Promise<void> {
  try {
    await ElMessageBox.confirm(
      "撤销后该策略不能恢复；历史任务版本仍保留原引用。",
      "撤销传输策略",
      {
        confirmButtonText: "确认撤销",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  policyActionId.value = policy.id;
  policiesError.value = null;
  try {
    await updateTransferPolicy(policy, { status: "REVOKED" });
    ElMessage.success("传输策略已撤销。");
    await loadPolicies();
  } catch (caught) {
    policiesError.value = caught;
  } finally {
    policyActionId.value = null;
  }
}

function showPolicyDetails(policy: TransferPolicy): void {
  detailPolicy.value = policy;
  detailsVisible.value = true;
}

async function loadAudit(
  append = false,
): Promise<void> {
  auditLoading.value = true;
  auditError.value = null;
  try {
    const page = await listProjectAuditEvents(props.project.id, {
      action: auditFilters.action.trim() || undefined,
      outcome: auditFilters.outcome || undefined,
      cursor: append ? auditNextCursor.value ?? undefined : undefined,
    });
    auditItems.value = append
      ? [...auditItems.value, ...page.items]
      : page.items;
    auditNextCursor.value = page.next_cursor;
    auditHasMore.value = page.has_more;
  } catch (caught) {
    auditError.value = caught;
    if (!append) auditItems.value = [];
  } finally {
    auditLoading.value = false;
  }
}

function policyApprovalThreshold(policy: TransferPolicy): number {
  return policy.classification === "STANDARD" ? 1 : 2;
}

function policyApprovalCount(policy: TransferPolicy): number {
  return policy.approvals.filter(
    (approval) => approval.decision === "APPROVED",
  ).length;
}

function actorName(userId: string): string {
  if (userId === auth.state.user?.id)
    return `${auth.state.user.display_name}（我）`;
  return (
    users.value.find((user) => user.id === userId)?.display_name ??
    `管理员 ${userId.slice(0, 8)}`
  );
}

function actionLabel(action: string): string {
  const labels: Record<string, string> = {
    ROLE_GRANTED: "授予项目角色",
    ROLE_REVOKED: "撤销项目角色",
    ENDPOINT_POLICY_CREATED: "创建网络准入策略",
    ENDPOINT_POLICY_UPDATED: "更新网络准入策略",
    ENDPOINT_POLICY_DISABLED: "停用网络准入策略",
    DATASOURCE_USAGE_GRANTED: "授予数据源用途",
    DATASOURCE_USAGE_REVOKED: "撤销数据源用途",
    TRANSFER_POLICY_CREATED: "创建传输策略",
    TRANSFER_POLICY_SUBMITTED: "提交传输策略",
    TRANSFER_POLICY_APPROVED: "批准传输策略",
    TRANSFER_POLICY_REJECTED: "拒绝传输策略",
    TRANSFER_POLICY_REVOKED: "撤销传输策略",
  };
  return labels[action] ?? action;
}

function statusDescription(policy: TransferPolicy): string {
  if (policy.status === "DRAFT") return "尚未提交审批";
  if (policy.status === "PENDING_APPROVAL")
    return `已批准 ${policyApprovalCount(policy)}/${policyApprovalThreshold(policy)}`;
  if (policy.status === "ACTIVE")
    return `达到 ${policyApprovalThreshold(policy)} 人门槛`;
  if (policy.status === "REJECTED") return "任一拒绝立即终止";
  return "已撤销，不可恢复";
}

function tableKey(table: TableSchema): string {
  return table.physical_table_identity_hash;
}

function normalizedSchema(
  detail: DatasourceAdminDetail | null,
  table: TableSchema,
): string {
  return detail?.engine === "MYSQL_8" ? "" : table.schema_name;
}

function grantKey(
  datasourceId: string,
  memberId: string,
): string {
  return `${datasourceId}:${memberId}`;
}

function isProjectRole(role: string): role is ProjectRole {
  return ["DEVELOPER", "OPERATOR", "VIEWER"].includes(role);
}

async function initialize(): Promise<void> {
  activeTab.value = props.canAdmin ? "members" : "policies";
  await Promise.all([loadPolicies(), loadAudit()]);
  if (props.canAdmin) {
    await loadMembers();
    await loadGrants();
  }
}

onMounted(() => void initialize());
watch(
  () => props.project.id,
  () => void initialize(),
);
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">项目安全边界</p>
        <h1>治理与授权</h1>
        <p>{{ project.name }} 的角色、数据源用途、传输范围审批与追加式审计。</p>
      </div>
      <el-button
        v-if="canAdmin"
        type="primary"
        :disabled="!egressReady"
        @click="openCreatePolicy"
      >
        新建传输策略
      </el-button>
    </header>

    <div class="readiness-strip">
      <div :class="{ 'readiness-item--blocked': !egressReady }" class="readiness-item">
        <strong>数据库出口</strong>
        <StateBadge :value="egressReady ? 'VERIFIED' : 'UNVERIFIED'" />
        <span>{{ egressReady ? "可读取真实元数据" : "元数据与连接安全阻断" }}</span>
      </div>
      <div :class="{ 'readiness-item--blocked': !workerReady }" class="readiness-item">
        <strong>执行链路</strong>
        <StateBadge :value="workerReady ? 'READY' : 'BLOCKED'" />
        <span>{{ workerReady ? "Worker / Runtime / Oracle / 对账已就绪" : "即使策略 ACTIVE 也不能运行" }}</span>
      </div>
    </div>

    <el-alert
      v-if="!workerReady || !egressReady"
      type="error"
      :closable="false"
      show-icon
      title="当前只允许查看或保存不依赖缺失组件的配置"
      description="页面不会把 ACTIVE、已保存或审批完成称为可运行。实际执行仍必须通过出口、Worker、Runtime、Oracle 和恢复对账门禁。"
    />

    <section class="content-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane v-if="canAdmin" label="项目成员" name="members">
          <div class="tab-intro">
            <div>
              <h2>项目角色</h2>
              <p>组织 Admin 为继承权限；项目内只能分配 Developer、Operator、Viewer，可多选并取并集。</p>
            </div>
            <el-button :loading="membersLoading" @click="loadMembers">刷新</el-button>
          </div>
          <ProblemPanel v-if="membersError" :error="membersError" @retry="loadMembers" />
          <el-skeleton v-if="membersLoading && !memberRows.length" :rows="5" animated />
          <EmptyState
            v-else-if="!memberRows.length && !membersError"
            title="没有可分配用户"
            description="请先在“用户与授权”中创建 ACTIVE 本地用户。"
          />
          <el-table v-else :data="memberRows" row-key="user.id">
            <el-table-column label="用户" min-width="230">
              <template #default="{ row }">
                <div class="primary-cell">
                  <strong>{{ row.user.display_name }}</strong>
                  <span>{{ row.user.email }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="继承权限" width="140">
              <template #default="{ row }">
                <StateBadge v-if="row.inheritedAdmin" value="ADMIN" />
                <span v-else>—</span>
              </template>
            </el-table-column>
            <el-table-column label="项目角色" min-width="420">
              <template #default="{ row }">
                <el-checkbox-group v-model="memberRoleDrafts[row.user.id]">
                  <el-checkbox value="DEVELOPER">开发者</el-checkbox>
                  <el-checkbox value="OPERATOR">操作员</el-checkbox>
                  <el-checkbox value="VIEWER">只读查看</el-checkbox>
                </el-checkbox-group>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="{ row }">
                <el-button
                  size="small"
                  type="primary"
                  :loading="memberSavingId === row.user.id"
                  @click="saveMemberRoles(row.user)"
                >
                  保存
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane v-if="canAdmin" label="数据源用途" name="grants">
          <div class="tab-intro">
            <div>
              <h2>源端与目标端使用授权</h2>
              <p>用途授权只允许项目成员引用数据源，不能绕过网络准入、传输策略、元数据复检或执行门禁。</p>
            </div>
            <el-button :loading="grantsLoading" @click="loadGrants">刷新</el-button>
          </div>
          <ProblemPanel v-if="grantsError" :error="grantsError" @retry="loadGrants" />
          <el-skeleton v-if="grantsLoading && !datasources.length" :rows="6" animated />
          <EmptyState
            v-else-if="!datasources.length && !grantsError"
            title="没有可授权的数据源"
            description="请先创建数据源并保留至少一名有项目角色的成员。"
          />
          <el-collapse v-else>
            <el-collapse-item
              v-for="datasource in datasources"
              :key="datasource.id"
              :name="datasource.id"
              :title="`${datasource.name} · ${datasource.engine === 'MYSQL_8' ? 'MySQL 8' : 'PostgreSQL 15'}`"
            >
              <EmptyState
                v-if="!grantableMembers.length"
                title="尚无项目成员"
                description="先在“项目成员”中分配 Developer、Operator 或 Viewer。"
              />
              <el-table v-else :data="grantableMembers" row-key="organization_member_id" size="small">
                <el-table-column label="成员" min-width="230">
                  <template #default="{ row }">
                    <div class="primary-cell">
                      <strong>{{ row.user.display_name }}</strong>
                      <span>{{ row.user.email }}</span>
                    </div>
                  </template>
                </el-table-column>
                <el-table-column label="项目角色" min-width="220">
                  <template #default="{ row }">
                    <div class="tag-list">
                      <StateBadge v-for="role in row.roles" :key="role" :value="role" />
                    </div>
                  </template>
                </el-table-column>
                <el-table-column label="允许用途" min-width="300">
                  <template #default="{ row }">
                    <el-checkbox-group
                      v-model="grantDrafts[grantKey(datasource.id, row.organization_member_id)]"
                    >
                      <el-checkbox value="SOURCE_USE">作为复制源</el-checkbox>
                      <el-checkbox value="TARGET_USE">作为复制目标</el-checkbox>
                    </el-checkbox-group>
                  </template>
                </el-table-column>
                <el-table-column label="操作" width="110">
                  <template #default="{ row }">
                    <el-button
                      size="small"
                      type="primary"
                      :loading="
                        grantSavingKey ===
                        grantKey(datasource.id, row.organization_member_id)
                      "
                      @click="saveGrant(datasource, row)"
                    >
                      保存
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>
            </el-collapse-item>
          </el-collapse>
        </el-tab-pane>

        <el-tab-pane label="传输策略" name="policies">
          <div class="tab-intro">
            <div>
              <h2>精确传输范围与独立审批</h2>
              <p>表、列、物理端点和哈希由服务端基于真实元数据固定；客户端不能自报 scope_hash。</p>
            </div>
            <div class="inline-actions">
              <el-button :loading="policiesLoading" @click="loadPolicies">刷新</el-button>
              <el-button
                v-if="canAdmin"
                type="primary"
                :disabled="!egressReady"
                @click="openCreatePolicy"
              >
                新建草稿
              </el-button>
            </div>
          </div>
          <ProblemPanel v-if="policiesError" :error="policiesError" @retry="loadPolicies" />
          <el-skeleton v-if="policiesLoading && !policies.length" :rows="6" animated />
          <EmptyState
            v-else-if="!policies.length && !policiesError"
            title="尚无传输策略"
            :description="
              canAdmin
                ? egressReady
                  ? '从真实源端与目标端元数据选择表和显式列，创建第一条草稿。'
                  : '数据库出口尚未验证，无法安全读取真实元数据。'
                : '请由组织 Admin 创建并完成独立审批。'
            "
            :action-label="canAdmin && egressReady ? '新建草稿' : undefined"
            @action="openCreatePolicy"
          />
          <el-table v-else :data="policies" row-key="id">
            <el-table-column label="范围" min-width="260">
              <template #default="{ row }">
                <div class="primary-cell">
                  <strong>
                    {{ row.scope_json.source.catalog }}.{{ row.scope_json.source.schema || "∅" }}.{{
                      row.scope_json.source.table
                    }}
                    →
                    {{ row.scope_json.target.catalog }}.{{ row.scope_json.target.schema || "∅" }}.{{
                      row.scope_json.target.table
                    }}
                  </strong>
                  <span>
                    源 {{ row.scope_json.source.allowed_columns.length }} 列 · 目标
                    {{ row.scope_json.target.allowed_columns.length }} 列
                  </span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="级别" width="120">
              <template #default="{ row }">
                {{ row.classification === "SENSITIVE" ? "敏感（双人）" : "标准（单人）" }}
              </template>
            </el-table-column>
            <el-table-column label="审批" min-width="170">
              <template #default="{ row }">
                <div class="primary-cell">
                  <strong>{{ policyApprovalCount(row) }}/{{ policyApprovalThreshold(row) }}</strong>
                  <span>{{ statusDescription(row) }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="150">
              <template #default="{ row }"><StateBadge :value="row.status" /></template>
            </el-table-column>
            <el-table-column label="范围哈希" min-width="160">
              <template #default="{ row }">
                <el-tooltip :content="row.scope_hash">
                  <code>{{ row.scope_hash.slice(0, 12) }}…</code>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="操作" min-width="310" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="showPolicyDetails(row)">详情</el-button>
                <el-button
                  v-if="canAdmin && row.status === 'DRAFT'"
                  size="small"
                  :disabled="!egressReady"
                  @click="openEditPolicy(row)"
                >
                  编辑
                </el-button>
                <el-button
                  v-if="canAdmin && row.status === 'DRAFT'"
                  size="small"
                  type="primary"
                  :loading="policyActionId === row.id"
                  @click="submitPolicy(row)"
                >
                  提交审批
                </el-button>
                <template v-if="canAdmin && row.status === 'PENDING_APPROVAL'">
                  <el-button
                    size="small"
                    type="success"
                    :disabled="row.requested_by === auth.state.user?.id"
                    @click="openDecision(row, 'APPROVED')"
                  >
                    批准
                  </el-button>
                  <el-button
                    size="small"
                    type="danger"
                    :disabled="row.requested_by === auth.state.user?.id"
                    @click="openDecision(row, 'REJECTED')"
                  >
                    拒绝
                  </el-button>
                </template>
                <el-button
                  v-if="canAdmin && row.status === 'ACTIVE'"
                  size="small"
                  type="danger"
                  plain
                  :loading="policyActionId === row.id"
                  @click="revokePolicy(row)"
                >
                  撤销
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="审计记录" name="audit">
          <div class="tab-intro">
            <div>
              <h2>追加式项目审计</h2>
              <p>只读展示后端事实、操作者、结果与链式哈希；界面不会修改或补写审计事件。</p>
            </div>
            <div class="inline-actions">
              <el-input v-model="auditFilters.action" clearable placeholder="按动作代码筛选" />
              <el-select v-model="auditFilters.outcome" clearable placeholder="全部结果">
                <el-option label="成功" value="SUCCEEDED" />
                <el-option label="拒绝" value="DENIED" />
                <el-option label="失败" value="FAILED" />
              </el-select>
              <el-button :loading="auditLoading" @click="loadAudit(false)">查询</el-button>
            </div>
          </div>
          <ProblemPanel v-if="auditError" :error="auditError" @retry="loadAudit(false)" />
          <el-skeleton v-if="auditLoading && !auditItems.length" :rows="6" animated />
          <EmptyState
            v-else-if="!auditItems.length && !auditError"
            title="当前筛选下没有审计事件"
            description="创建角色、用途授权、策略审批或执行事实后会由服务端追加记录。"
          />
          <el-timeline v-else>
            <el-timeline-item
              v-for="event in auditItems"
              :key="event.event_id"
              :timestamp="formatTime(event.occurred_at)"
              placement="top"
            >
              <article class="audit-card">
                <div class="audit-card__heading">
                  <strong>{{ actionLabel(event.action) }}</strong>
                  <StateBadge :value="event.outcome" />
                </div>
                <p>
                  {{ event.actor.display_name || "系统" }}
                  <span v-if="event.target.name"> · {{ event.target.name }}</span>
                  <span v-else-if="event.target.type"> · {{ event.target.type }}</span>
                </p>
                <div class="audit-card__meta">
                  <span>序号 {{ event.sequence }}</span>
                  <span v-if="event.reason_code">原因 {{ event.reason_code }}</span>
                  <span v-if="event.changes.changed_fields.length">
                    字段 {{ event.changes.changed_fields.join("、") }}
                  </span>
                  <el-tooltip :content="event.integrity.event_hash">
                    <code>hash {{ event.integrity.event_hash.slice(0, 12) }}…</code>
                  </el-tooltip>
                </div>
              </article>
            </el-timeline-item>
          </el-timeline>
          <div v-if="auditHasMore" class="load-more">
            <el-button :loading="auditLoading" @click="loadAudit(true)">加载更多</el-button>
          </div>
        </el-tab-pane>
      </el-tabs>
    </section>

    <el-dialog
      v-model="policyDialogVisible"
      :title="editingPolicy ? '编辑传输策略草稿' : '新建传输策略草稿'"
      width="min(1040px, 97vw)"
      destroy-on-close
    >
      <ProblemPanel v-if="policyError" :error="policyError" :show-retry="false" />
      <ProblemPanel v-if="metadataError" :error="metadataError" :show-retry="false" />
      <el-alert
        type="info"
        :closable="false"
        title="两次真实校验"
        description="浏览器先读取真实元数据帮助选择；保存时服务端会再次探测并独立固定物理端点、表、显式列与 scope_hash。"
      />
      <div class="form-grid form-grid--two">
        <el-form label-position="top">
          <h3>1. 选择源数据</h3>
          <el-form-item label="源数据源" required>
            <el-select v-model="policyForm.sourceDatasourceId" class="full-width" filterable>
              <el-option
                v-for="datasource in activeDatasources"
                :key="datasource.id"
                :label="`${datasource.name} · ${datasource.engine === 'MYSQL_8' ? 'MySQL 8' : 'PostgreSQL 15'}`"
                :value="datasource.id"
              />
            </el-select>
          </el-form-item>
        </el-form>
        <el-form label-position="top">
          <h3>2. 选择目标数据</h3>
          <el-form-item label="目标数据源" required>
            <el-select v-model="policyForm.targetDatasourceId" class="full-width" filterable>
              <el-option
                v-for="datasource in activeDatasources"
                :key="datasource.id"
                :label="`${datasource.name} · ${datasource.engine === 'MYSQL_8' ? 'MySQL 8' : 'PostgreSQL 15'}`"
                :value="datasource.id"
              />
            </el-select>
          </el-form-item>
        </el-form>
      </div>
      <div class="metadata-action">
        <el-button
          type="primary"
          plain
          :loading="metadataLoading"
          :disabled="
            !policyForm.sourceDatasourceId ||
            !policyForm.targetDatasourceId ||
            !egressReady
          "
          @click="loadPolicyMetadata"
        >
          读取两端真实表与字段
        </el-button>
        <span>只读元数据访问仍受凭据、DNS 重绑定和出口策略保护。</span>
      </div>
      <el-alert
        v-if="metadataIncomplete"
        type="error"
        :closable="false"
        title="表列表超过当前 API 可完整分页的范围"
        description="为防止从不完整元数据中误选，当前草稿不能保存。请先缩小后端元数据查询契约。"
      />
      <div v-if="sourceDetail && targetDetail" class="form-grid form-grid--two scope-columns">
        <section class="scope-side">
          <h3>源表与允许列</h3>
          <el-form label-position="top">
            <el-form-item label="真实源表" required>
              <el-select
                v-model="policyForm.sourceTableKey"
                class="full-width"
                filterable
                @change="sourceTableChanged"
              >
                <el-option
                  v-for="table in sourceTables"
                  :key="tableKey(table)"
                  :label="`${table.schema_name}.${table.table_name}`"
                  :value="tableKey(table)"
                  :disabled="!table.oracle_compatible"
                />
              </el-select>
            </el-form-item>
            <el-form-item label="列选择方式" required>
              <el-radio-group v-model="policyForm.sourceSelectionMode" @change="sourceModeChanged">
                <el-radio-button value="ALL_COLUMNS">当前全部列</el-radio-button>
                <el-radio-button value="SELECTED_COLUMNS">指定列</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <div v-if="selectedSourceTable" class="column-picker">
              <div v-if="policyForm.sourceSelectionMode === 'ALL_COLUMNS'" class="tag-list">
                <el-tag v-for="column in sourceColumns" :key="column.name" effect="plain">
                  {{ column.name }}
                </el-tag>
              </div>
              <el-checkbox-group v-else v-model="policyForm.sourceColumns">
                <el-checkbox
                  v-for="column in sourceColumns"
                  :key="column.name"
                  :value="column.name"
                  :disabled="!column.oracle_supported"
                >
                  {{ column.name }} · {{ column.native_type }}
                </el-checkbox>
              </el-checkbox-group>
            </div>
          </el-form>
        </section>
        <section class="scope-side">
          <h3>目标表与允许列</h3>
          <el-form label-position="top">
            <el-form-item label="真实目标表" required>
              <el-select
                v-model="policyForm.targetTableKey"
                class="full-width"
                filterable
                @change="targetTableChanged"
              >
                <el-option
                  v-for="table in targetTables"
                  :key="tableKey(table)"
                  :label="`${table.schema_name}.${table.table_name}`"
                  :value="tableKey(table)"
                  :disabled="
                    !table.oracle_compatible ||
                    !table.target_insert_compatible
                  "
                />
              </el-select>
            </el-form-item>
            <el-form-item label="列选择方式" required>
              <el-radio-group v-model="policyForm.targetSelectionMode" @change="targetModeChanged">
                <el-radio-button value="ALL_COLUMNS">当前全部列</el-radio-button>
                <el-radio-button value="SELECTED_COLUMNS">指定列</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <div v-if="selectedTargetTable" class="column-picker">
              <div v-if="policyForm.targetSelectionMode === 'ALL_COLUMNS'" class="tag-list">
                <el-tag v-for="column in targetColumns" :key="column.name" effect="plain">
                  {{ column.name }}
                </el-tag>
              </div>
              <el-checkbox-group v-else v-model="policyForm.targetColumns">
                <el-checkbox
                  v-for="column in targetColumns"
                  :key="column.name"
                  :value="column.name"
                  :disabled="
                    !column.oracle_supported || column.generated
                  "
                >
                  {{ column.name }} · {{ column.native_type }}
                </el-checkbox>
              </el-checkbox-group>
            </div>
          </el-form>
        </section>
      </div>
      <el-alert
        v-if="
          selectedSourceTable &&
          selectedTargetTable &&
          selectedSourceTable.physical_table_identity_hash ===
            selectedTargetTable.physical_table_identity_hash
        "
        type="error"
        :closable="false"
        title="源表和目标表解析为同一物理表"
        description="V1 禁止同表自复制，不能保存。服务端也会再次阻断。"
      />
      <el-form label-position="top">
        <el-form-item label="审批级别" required>
          <el-radio-group v-model="policyForm.classification">
            <el-radio value="STANDARD">标准：1 名非申请人 Admin 批准</el-radio>
            <el-radio value="SENSITIVE">敏感：2 名不同的非申请人 Admin 批准</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="policyDialogVisible = false">取消</el-button>
        <el-button
          type="primary"
          :disabled="!canSavePolicy"
          :loading="policySubmitting"
          @click="savePolicy"
        >
          {{ editingPolicy ? "保存并重置审批" : "创建草稿" }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="decisionVisible"
      :title="decisionForm.decision === 'APPROVED' ? '批准传输策略' : '拒绝传输策略'"
      width="min(560px, 94vw)"
      destroy-on-close
    >
      <ProblemPanel v-if="policyError" :error="policyError" :show-retry="false" />
      <el-alert
        :type="decisionForm.decision === 'APPROVED' ? 'warning' : 'error'"
        :closable="false"
        :title="
          decisionForm.decision === 'APPROVED'
            ? '审批固定当前范围哈希'
            : '拒绝会立即结束本轮审批'
        "
        :description="
          decisionPolicy
            ? `scope_hash：${decisionPolicy.scope_hash}`
            : ''
        "
      />
      <el-form label-position="top">
        <el-form-item label="审批意见">
          <el-input
            v-model="decisionForm.comment"
            type="textarea"
            maxlength="500"
            show-word-limit
            :rows="4"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="decisionVisible = false">取消</el-button>
        <el-button
          :type="decisionForm.decision === 'APPROVED' ? 'success' : 'danger'"
          :loading="policySubmitting"
          @click="saveDecision"
        >
          {{ decisionForm.decision === "APPROVED" ? "确认批准" : "确认拒绝" }}
        </el-button>
      </template>
    </el-dialog>

    <el-drawer
      v-model="detailsVisible"
      title="传输策略详情"
      size="min(760px, 96vw)"
    >
      <template v-if="detailPolicy">
        <dl class="detail-list">
          <div><dt>状态</dt><dd><StateBadge :value="detailPolicy.status" /></dd></div>
          <div>
            <dt>审批级别</dt>
            <dd>{{ detailPolicy.classification === "SENSITIVE" ? "敏感 · 2 名独立 Admin" : "标准 · 1 名独立 Admin" }}</dd>
          </div>
          <div><dt>申请人</dt><dd>{{ actorName(detailPolicy.requested_by) }}</dd></div>
          <div><dt>生效时间</dt><dd>{{ formatTime(detailPolicy.activated_at) }}</dd></div>
          <div class="detail-list__wide"><dt>范围哈希</dt><dd><code>{{ detailPolicy.scope_hash }}</code></dd></div>
        </dl>
        <el-divider content-position="left">源端固定范围</el-divider>
        <dl class="detail-list">
          <div><dt>Catalog</dt><dd>{{ detailPolicy.scope_json.source.catalog }}</dd></div>
          <div><dt>Schema</dt><dd>{{ detailPolicy.scope_json.source.schema || "空哨兵（MySQL）" }}</dd></div>
          <div><dt>表</dt><dd>{{ detailPolicy.scope_json.source.table }}</dd></div>
          <div class="detail-list__wide">
            <dt>显式列</dt>
            <dd class="tag-list">
              <el-tag
                v-for="column in detailPolicy.scope_json.source.allowed_columns"
                :key="column"
                effect="plain"
              >
                {{ column }}
              </el-tag>
            </dd>
          </div>
        </dl>
        <el-divider content-position="left">目标端固定范围</el-divider>
        <dl class="detail-list">
          <div><dt>Catalog</dt><dd>{{ detailPolicy.scope_json.target.catalog }}</dd></div>
          <div><dt>Schema</dt><dd>{{ detailPolicy.scope_json.target.schema || "空哨兵（MySQL）" }}</dd></div>
          <div><dt>表</dt><dd>{{ detailPolicy.scope_json.target.table }}</dd></div>
          <div class="detail-list__wide">
            <dt>显式列</dt>
            <dd class="tag-list">
              <el-tag
                v-for="column in detailPolicy.scope_json.target.allowed_columns"
                :key="column"
                effect="plain"
              >
                {{ column }}
              </el-tag>
            </dd>
          </div>
        </dl>
        <el-divider content-position="left">审批记录</el-divider>
        <EmptyState
          v-if="!detailPolicy.approvals.length"
          title="尚无审批"
          description="草稿提交后，由非申请人组织 Admin 独立审批。"
        />
        <el-table v-else :data="detailPolicy.approvals" row-key="id" size="small">
          <el-table-column label="审批人" min-width="170">
            <template #default="{ row }">{{ actorName(row.approved_by) }}</template>
          </el-table-column>
          <el-table-column label="决定" width="110">
            <template #default="{ row }"><StateBadge :value="row.decision" /></template>
          </el-table-column>
          <el-table-column prop="comment" label="意见" min-width="190">
            <template #default="{ row }">{{ row.comment || "—" }}</template>
          </el-table-column>
          <el-table-column label="时间" min-width="170">
            <template #default="{ row }">{{ formatTime(row.decided_at) }}</template>
          </el-table-column>
        </el-table>
      </template>
    </el-drawer>
  </div>
</template>
