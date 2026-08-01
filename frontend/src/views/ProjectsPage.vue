<script setup lang="ts">
import { ElMessage, ElMessageBox } from "element-plus";
import { reactive, ref } from "vue";

import { newIdempotencyKey } from "../api/client";
import { createProject, updateProject } from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import type { Project } from "../types";

const props = defineProps<{
  projects: Project[];
  loading: boolean;
  error: unknown;
  isAdmin: boolean;
  selectedProjectId: string | null;
}>();

const emit = defineEmits<{
  refresh: [];
  select: [project: Project];
}>();

const createVisible = ref(false);
const editVisible = ref(false);
const submitting = ref(false);
const actionError = ref<unknown>(null);
const editing = ref<Project | null>(null);
const createForm = reactive({ name: "", slug: "", description: "" });
const editForm = reactive({ name: "", description: "" });
const createKey = ref(newIdempotencyKey());

function openCreate(): void {
  createForm.name = "";
  createForm.slug = "";
  createForm.description = "";
  actionError.value = null;
  createKey.value = newIdempotencyKey();
  createVisible.value = true;
}

function openEdit(project: Project): void {
  editing.value = project;
  editForm.name = project.name;
  editForm.description = project.description ?? "";
  actionError.value = null;
  editVisible.value = true;
}

async function submitCreate(): Promise<void> {
  submitting.value = true;
  actionError.value = null;
  try {
    const project = await createProject(
      {
        name: createForm.name.trim(),
        slug: createForm.slug.trim(),
        description: createForm.description.trim() || null,
      },
      createKey.value,
    );
    createVisible.value = false;
    ElMessage.success("项目已创建。");
    emit("refresh");
    emit("select", project);
  } catch (caught) {
    actionError.value = caught;
  } finally {
    submitting.value = false;
  }
}

async function submitEdit(): Promise<void> {
  if (!editing.value) return;
  submitting.value = true;
  actionError.value = null;
  try {
    await updateProject(editing.value, {
      name: editForm.name.trim(),
      description: editForm.description.trim() || null,
    });
    editVisible.value = false;
    ElMessage.success("项目资料已更新。");
    emit("refresh");
  } catch (caught) {
    actionError.value = caught;
  } finally {
    submitting.value = false;
  }
}

async function archive(project: Project): Promise<void> {
  try {
    await ElMessageBox.prompt(
      `归档后项目只读，历史执行和审计保留。请输入项目标识“${project.slug}”确认。`,
      "归档项目",
      {
        confirmButtonText: "归档项目",
        cancelButtonText: "取消",
        inputValidator: (value) => value === project.slug || "项目标识不一致",
        type: "warning",
      },
    );
    await updateProject(project, { status: "ARCHIVED" });
    ElMessage.success("项目已归档。");
    emit("refresh");
  } catch (caught) {
    if (caught !== "cancel" && caught !== "close") actionError.value = caught;
  }
}
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">系统管理</p>
        <h1>项目管理</h1>
        <p>项目是数据源、复制任务、执行与审计的隔离边界。</p>
      </div>
      <el-button v-if="isAdmin" type="primary" @click="openCreate">新建项目</el-button>
    </header>

    <ProblemPanel v-if="error" :error="error" @retry="emit('refresh')" />
    <ProblemPanel v-if="actionError" :error="actionError" :show-retry="false" />
    <el-skeleton v-if="loading && !projects.length" :rows="6" animated />

    <EmptyState
      v-else-if="!projects.length && !error"
      title="还没有可访问的项目"
      :description="
        isAdmin
          ? '创建第一个项目后，才能配置数据源和复制任务。'
          : '你尚未被分配项目，请联系 Admin。'
      "
      :action-label="isAdmin ? '新建项目' : undefined"
      @action="openCreate"
    />

    <section v-else class="content-card">
      <el-table :data="projects" row-key="id">
        <el-table-column label="项目" min-width="220">
          <template #default="{ row }">
            <div class="primary-cell">
              <strong>{{ row.name }}</strong>
              <code>{{ row.slug }}</code>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="说明" min-width="260">
          <template #default="{ row }">{{ row.description || "—" }}</template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }"><StateBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="270" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              :type="row.id === selectedProjectId ? 'primary' : 'default'"
              @click="emit('select', row)"
            >
              {{ row.id === selectedProjectId ? "当前项目" : "进入项目" }}
            </el-button>
            <el-button v-if="isAdmin && row.status === 'ACTIVE'" size="small" @click="openEdit(row)">
              编辑
            </el-button>
            <el-button
              v-if="isAdmin && row.status === 'ACTIVE'"
              size="small"
              type="danger"
              plain
              @click="archive(row)"
            >
              归档
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog v-model="createVisible" title="新建项目" width="min(560px, 94vw)" destroy-on-close>
      <ProblemPanel v-if="actionError" :error="actionError" :show-retry="false" />
      <el-form label-position="top" @submit.prevent="submitCreate">
        <el-form-item label="项目名称" required>
          <el-input v-model="createForm.name" maxlength="128" />
        </el-form-item>
        <el-form-item label="项目标识" required>
          <el-input v-model="createForm.slug" maxlength="64" placeholder="例如 data-migration" />
          <span class="field-help">3–64 位，以小写字母开头，只含小写字母、数字和连字符；创建后不可改。</span>
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="createForm.description" type="textarea" maxlength="1000" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="
            !createForm.name.trim() ||
            !/^[a-z][a-z0-9-]{2,63}$/.test(createForm.slug.trim())
          "
          @click="submitCreate"
        >
          创建项目
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="编辑项目" width="min(560px, 94vw)" destroy-on-close>
      <ProblemPanel v-if="actionError" :error="actionError" :show-retry="false" />
      <el-form label-position="top" @submit.prevent="submitEdit">
        <el-form-item label="项目名称" required>
          <el-input v-model="editForm.name" maxlength="128" />
        </el-form-item>
        <el-form-item label="项目标识">
          <el-input :model-value="editing?.slug" disabled />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="editForm.description" type="textarea" maxlength="1000" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" :disabled="!editForm.name.trim()" @click="submitEdit">
          保存修改
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
