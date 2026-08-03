<script setup lang="ts">
import { ElMessage } from "element-plus";
import { computed, onMounted, reactive, ref } from "vue";

import { newIdempotencyKey } from "../api/client";
import {
  createEndpointPolicy,
  listEndpointPolicies,
  updateEndpointPolicy,
} from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import type {
  EndpointPolicy,
  EndpointPolicyInput,
  Engine,
} from "../types";

const props = defineProps<{
  egressReady: boolean;
}>();

type FormMode = "create" | "edit";

const items = ref<EndpointPolicy[]>([]);
const loading = ref(false);
const error = ref<unknown>(null);
const dialogVisible = ref(false);
const submitting = ref(false);
const formMode = ref<FormMode>("create");
const editingPolicy = ref<EndpointPolicy | null>(null);
const createKey = ref(newIdempotencyKey());
const form = reactive({
  name: "",
  engine: "MYSQL_8" as Engine,
  hostKind: "EXACT_FQDN" as "EXACT_FQDN" | "EXACT_IP",
  hostValue: "",
  allowedCidrsText: "",
  allowedPortsText: "",
  tlsRequired: true,
  dnsTtlCeilingSeconds: 60,
  status: "ACTIVE" as "ACTIVE" | "DISABLED",
});

const parsedCidrs = computed(() => parseTokens(form.allowedCidrsText));
const parsedPorts = computed(() =>
  parseTokens(form.allowedPortsText)
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value >= 1 && value <= 65535),
);
const portsValid = computed(
  () =>
    parsedPorts.value.length > 0 &&
    parsedPorts.value.length === parseTokens(form.allowedPortsText).length &&
    parsedPorts.value.length <= 16,
);
const canSubmit = computed(
  () =>
    form.name.trim().length > 0 &&
    form.hostValue.trim().length > 0 &&
    parsedCidrs.value.length > 0 &&
    parsedCidrs.value.length <= 64 &&
    portsValid.value &&
    form.dnsTtlCeilingSeconds >= 1 &&
    form.dnsTtlCeilingSeconds <= 3600,
);

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    items.value = (await listEndpointPolicies()).items;
  } catch (caught) {
    error.value = caught;
    items.value = [];
  } finally {
    loading.value = false;
  }
}

function openCreate(): void {
  formMode.value = "create";
  editingPolicy.value = null;
  form.name = "";
  form.engine = "MYSQL_8";
  form.hostKind = "EXACT_FQDN";
  form.hostValue = "";
  form.allowedCidrsText = "";
  form.allowedPortsText = "3306";
  form.tlsRequired = true;
  form.dnsTtlCeilingSeconds = 60;
  form.status = "ACTIVE";
  createKey.value = newIdempotencyKey();
  error.value = null;
  dialogVisible.value = true;
}

function openEdit(policy: EndpointPolicy): void {
  formMode.value = "edit";
  editingPolicy.value = policy;
  const revision = policy.current_revision;
  form.name = policy.name;
  form.engine = revision.engine;
  form.hostKind = revision.host_kind;
  form.hostValue = revision.host_value;
  form.allowedCidrsText = revision.allowed_cidrs.join("\n");
  form.allowedPortsText = revision.allowed_ports.join(", ");
  form.tlsRequired = revision.tls_required;
  form.dnsTtlCeilingSeconds = revision.dns_ttl_ceiling_seconds;
  form.status = policy.status;
  error.value = null;
  dialogVisible.value = true;
}

function engineChanged(): void {
  if (formMode.value !== "create") return;
  form.allowedPortsText = form.engine === "MYSQL_8" ? "3306" : "5432";
}

async function submit(): Promise<void> {
  if (!canSubmit.value) return;
  submitting.value = true;
  error.value = null;
  const input: EndpointPolicyInput = {
    name: form.name.trim(),
    engine: form.engine,
    host_kind: form.hostKind,
    host_value: form.hostValue.trim(),
    allowed_cidrs: parsedCidrs.value,
    allowed_ports: [...new Set(parsedPorts.value)].sort((left, right) => left - right),
    tls_required: form.tlsRequired,
    dns_ttl_ceiling_seconds: form.dnsTtlCeilingSeconds,
  };
  try {
    if (formMode.value === "create") {
      await createEndpointPolicy(input, createKey.value);
      ElMessage.success("网络准入策略已创建。运行时仍会重新解析 DNS 并复检出口。");
    } else if (editingPolicy.value) {
      const { engine: _engine, ...patch } = input;
      await updateEndpointPolicy(editingPolicy.value, {
        ...patch,
        status: form.status,
      });
      ElMessage.success("网络准入策略已生成新修订。历史引用不会跟随改变。");
    }
    dialogVisible.value = false;
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
  }
}

function parseTokens(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\s,，;；]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

function engineLabel(engine: Engine): string {
  return engine === "MYSQL_8" ? "MySQL 8" : "PostgreSQL 15";
}

onMounted(() => void load());
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">组织级网络边界</p>
        <h1>网络准入策略</h1>
        <p>先允许精确数据库端点，再创建数据源。策略只定义准入，不代表数据库已经可连接。</p>
      </div>
      <el-button type="primary" @click="openCreate">新建准入策略</el-button>
    </header>

    <el-alert
      v-if="!props.egressReady"
      type="error"
      :closable="false"
      show-icon
      title="容器出口策略尚未通过安装级验证"
      description="可以先保存配置，但连接测试、元数据读取和实际复制仍会由服务端安全阻断。ACTIVE 只表示策略启用，不等于网络可运行。"
    />
    <el-alert
      v-else
      type="success"
      :closable="false"
      show-icon
      title="容器出口策略已验证"
      description="每次 TEST、METADATA、DATAX、ORACLE 和恢复探测仍会重新执行 DNS 与出口复检。"
    />

    <ProblemPanel v-if="error && !dialogVisible" :error="error" @retry="load" />
    <el-skeleton v-if="loading && !items.length" :rows="6" animated />
    <EmptyState
      v-else-if="!items.length && !error"
      title="尚未配置网络准入策略"
      description="新建一条精确 FQDN 或 IP 策略；不支持通配域名，也不会自动开放任意网络。"
      action-label="新建准入策略"
      @action="openCreate"
    />

    <section v-else class="content-card">
      <el-table :data="items" row-key="id">
        <el-table-column label="策略" min-width="210">
          <template #default="{ row }">
            <div class="primary-cell">
              <strong>{{ row.name }}</strong>
              <span>修订 {{ row.current_revision_no }} · {{ engineLabel(row.current_revision.engine) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="精确端点" min-width="250">
          <template #default="{ row }">
            <div class="primary-cell">
              <code>{{ row.current_revision.host_value }}</code>
              <span>{{ row.current_revision.host_kind === "EXACT_IP" ? "精确 IP" : "精确域名" }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="允许端口" min-width="150">
          <template #default="{ row }">
            <div class="tag-list">
              <el-tag v-for="port in row.current_revision.allowed_ports" :key="port" effect="plain">
                {{ port }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="TLS" width="100">
          <template #default="{ row }">{{ row.current_revision.tls_required ? "必须" : "非必须" }}</template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }"><StateBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="系统网络策略版本" min-width="250">
          <template #default="{ row }">
            <div class="primary-cell">
              <code>解析器：{{ row.current_revision.resolver_policy_version }}</code>
              <code>出口：{{ row.current_revision.egress_policy_version }}</code>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="策略哈希" min-width="180">
          <template #default="{ row }">
            <el-tooltip :content="row.current_revision.policy_hash">
              <code>{{ row.current_revision.policy_hash.slice(0, 12) }}…</code>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="openEdit(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog
      v-model="dialogVisible"
      :title="formMode === 'create' ? '新建网络准入策略' : '编辑网络准入策略'"
      width="min(760px, 96vw)"
      destroy-on-close
    >
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <el-alert
        type="info"
        :closable="false"
        title="系统网络策略版本由服务端固定"
        description="管理员不需要也不能猜测或编辑版本。服务端会从当前安装验证结果派生，并在策略修订中只读返回；真实连接时仍会复检 DNS、出口规则与对端 IP。"
      />
      <dl v-if="editingPolicy" class="detail-list">
        <div>
          <dt>解析器策略版本</dt>
          <dd><code>{{ editingPolicy.current_revision.resolver_policy_version }}</code></dd>
        </div>
        <div>
          <dt>出口策略版本</dt>
          <dd><code>{{ editingPolicy.current_revision.egress_policy_version }}</code></dd>
        </div>
      </dl>
      <el-form label-position="top" @submit.prevent="submit">
        <div class="form-grid form-grid--two">
          <el-form-item label="策略名称" required>
            <el-input v-model="form.name" maxlength="128" />
          </el-form-item>
          <el-form-item label="数据库类型" required>
            <el-select
              v-model="form.engine"
              class="full-width"
              :disabled="formMode === 'edit'"
              @change="engineChanged"
            >
              <el-option label="MySQL 8" value="MYSQL_8" />
              <el-option label="PostgreSQL 15" value="POSTGRESQL_15" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-grid form-grid--two">
          <el-form-item label="端点类型" required>
            <el-radio-group v-model="form.hostKind">
              <el-radio-button value="EXACT_FQDN">精确域名</el-radio-button>
              <el-radio-button value="EXACT_IP">精确 IP</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="端点值" required>
            <el-input
              v-model="form.hostValue"
              maxlength="253"
              :placeholder="form.hostKind === 'EXACT_IP' ? '例如 10.10.8.21' : '例如 db.internal.example'"
            />
          </el-form-item>
        </div>
        <el-form-item label="允许的目标网络（CIDR）" required>
          <el-input
            v-model="form.allowedCidrsText"
            type="textarea"
            :rows="3"
            placeholder="每行一个，例如 10.10.8.0/24"
          />
          <span class="field-help">DNS 解析出的所有地址都必须落在这些网络中；不接受任意网段通配。</span>
          <span v-if="parsedCidrs.length > 64" class="field-error">一条策略最多允许 64 个目标网络。</span>
        </el-form-item>
        <div class="form-grid form-grid--two">
          <el-form-item label="允许端口" required>
            <el-input v-model="form.allowedPortsText" placeholder="例如 3306，多个端口用逗号分隔" />
            <span v-if="!portsValid && form.allowedPortsText" class="field-error">
              请输入最多 16 个 1–65535 的整数端口。
            </span>
          </el-form-item>
          <el-form-item label="DNS 结果最长保留秒数" required>
            <el-input-number
              v-model="form.dnsTtlCeilingSeconds"
              :min="1"
              :max="3600"
              controls-position="right"
            />
          </el-form-item>
        </div>
        <el-form-item label="连接必须使用 TLS">
          <el-switch v-model="form.tlsRequired" inline-prompt active-text="必须" inactive-text="非必须" />
        </el-form-item>
        <el-form-item v-if="formMode === 'edit'" label="策略状态" required>
          <el-radio-group v-model="form.status">
            <el-radio-button value="ACTIVE">启用</el-radio-button>
            <el-radio-button value="DISABLED">停用</el-radio-button>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="form-actions form-actions--spread">
          <span class="muted">
            {{ formMode === "edit" ? `当前修订创建于 ${formatTime(editingPolicy?.current_revision.created_at)}` : "" }}
          </span>
          <div class="inline-actions">
            <el-button @click="dialogVisible = false">取消</el-button>
            <el-button type="primary" :disabled="!canSubmit" :loading="submitting" @click="submit">
              {{ formMode === "create" ? "创建策略" : "保存新修订" }}
            </el-button>
          </div>
        </div>
      </template>
    </el-dialog>
  </div>
</template>
