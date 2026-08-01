<script setup lang="ts">
import { ElMessage } from "element-plus";
import { onMounted, reactive, ref } from "vue";

import { newIdempotencyKey } from "../api/client";
import { createUser, listUsers } from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import type { User } from "../types";

const users = ref<User[]>([]);
const loading = ref(false);
const error = ref<unknown>(null);
const dialogVisible = ref(false);
const submitting = ref(false);
const form = reactive({
  email: "",
  displayName: "",
  temporaryPassword: "",
  confirmPassword: "",
});
const createKey = ref(newIdempotencyKey());

async function load(): Promise<void> {
  loading.value = true;
  error.value = null;
  try {
    users.value = (await listUsers()).items;
  } catch (caught) {
    error.value = caught;
  } finally {
    loading.value = false;
  }
}

function openCreate(): void {
  form.email = "";
  form.displayName = "";
  form.temporaryPassword = "";
  form.confirmPassword = "";
  createKey.value = newIdempotencyKey();
  dialogVisible.value = true;
}

async function submit(): Promise<void> {
  submitting.value = true;
  error.value = null;
  try {
    await createUser(
      {
        email: form.email.trim(),
        display_name: form.displayName.trim(),
        temporary_password: form.temporaryPassword,
      },
      createKey.value,
    );
    dialogVisible.value = false;
    ElMessage.success("用户已创建；首次登录必须修改临时密码。");
    await load();
  } catch (caught) {
    error.value = caught;
  } finally {
    submitting.value = false;
    form.temporaryPassword = "";
    form.confirmPassword = "";
  }
}

onMounted(() => void load());
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">系统管理</p>
        <h1>用户与授权</h1>
        <p>本页只显示后端返回的本地账号和角色事实；最终权限始终由服务端执行。</p>
      </div>
      <el-button type="primary" @click="openCreate">新建用户</el-button>
    </header>

    <ProblemPanel v-if="error" :error="error" @retry="load" />
    <el-skeleton v-if="loading && !users.length" :rows="6" animated />
    <EmptyState
      v-else-if="!users.length && !error"
      title="没有用户"
      description="除首次 Admin 外，后续账号由 Admin 创建。"
      action-label="新建用户"
      @action="openCreate"
    />
    <section v-else class="content-card">
      <el-table :data="users" row-key="id">
        <el-table-column label="用户" min-width="240">
          <template #default="{ row }">
            <div class="primary-cell"><strong>{{ row.display_name }}</strong><span>{{ row.email }}</span></div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120">
          <template #default="{ row }"><StateBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="角色" min-width="260">
          <template #default="{ row }">
            <span v-if="!row.role_assignments.length">—</span>
            <div v-else class="tag-list">
              <el-tag
                v-for="assignment in row.role_assignments"
                :key="`${assignment.scope_type}-${assignment.scope_id}`"
                effect="plain"
              >
                {{ assignment.roles.join(" / ") }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="必须改密" width="120">
          <template #default="{ row }">{{ row.must_change_password ? "是" : "否" }}</template>
        </el-table-column>
        <el-table-column label="更新时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog v-model="dialogVisible" title="新建本地用户" width="min(560px, 94vw)" destroy-on-close>
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item label="登录邮箱" required>
          <el-input v-model="form.email" autocomplete="off" maxlength="254" />
        </el-form-item>
        <el-form-item label="显示名" required>
          <el-input v-model="form.displayName" maxlength="128" />
        </el-form-item>
        <el-form-item label="临时密码" required>
          <el-input
            v-model="form.temporaryPassword"
            type="password"
            autocomplete="new-password"
            maxlength="256"
            show-password
          />
          <span class="field-help">至少 12 个字符；响应不会回显密码。</span>
        </el-form-item>
        <el-form-item label="确认临时密码" required>
          <el-input
            v-model="form.confirmPassword"
            type="password"
            autocomplete="new-password"
            maxlength="256"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="
            !form.email.trim() ||
            !form.displayName.trim() ||
            form.temporaryPassword.length < 12 ||
            form.temporaryPassword !== form.confirmPassword
          "
          @click="submit"
        >
          创建用户
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
