<script setup lang="ts">
import { ElMessage } from "element-plus";
import {
  computed,
  defineAsyncComponent,
  onBeforeUnmount,
  onMounted,
  reactive,
  ref,
} from "vue";

import { listProjects } from "../api/resources";
import HealthPanel from "../components/HealthPanel.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime } from "../lib/display";
import { useAuth } from "../state/auth";
import type { HealthResponse, Project } from "../types";

const DatasourcesPage = defineAsyncComponent(() => import("./DatasourcesPage.vue"));
const EndpointPoliciesPage = defineAsyncComponent(() => import("./EndpointPoliciesPage.vue"));
const ExecutionsPage = defineAsyncComponent(() => import("./ExecutionsPage.vue"));
const GovernancePage = defineAsyncComponent(() => import("./GovernancePage.vue"));
const HomePage = defineAsyncComponent(() => import("./HomePage.vue"));
const JobsPage = defineAsyncComponent(() => import("./JobsPage.vue"));
const ProjectsPage = defineAsyncComponent(() => import("./ProjectsPage.vue"));
const UsersPage = defineAsyncComponent(() => import("./UsersPage.vue"));

const props = defineProps<{
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: string | null;
}>();

const emit = defineEmits<{
  refreshHealth: [];
}>();

type PageKey =
  | "home"
  | "projects"
  | "datasources"
  | "governance"
  | "jobs"
  | "executions"
  | "endpoint-policies"
  | "users"
  | "system";

const auth = useAuth();
const page = ref<PageKey>("home");
const projects = ref<Project[]>([]);
const projectsLoading = ref(false);
const projectsError = ref<unknown>(null);
const selectedProjectId = ref<string | null>(null);
const mobileNavOpen = ref(false);
const profileVisible = ref(false);
const passwordLoading = ref(false);
const profileError = ref<unknown>(null);
const passwordForm = reactive({
  current: "",
  next: "",
  confirm: "",
});
const runJobId = ref<string | null>(null);
const requestedExecutionId = ref<string | null>(null);

const selectedProject = computed(
  () => projects.value.find((project) => project.id === selectedProjectId.value) ?? null,
);
const currentRoles = computed(() =>
  selectedProject.value ? auth.rolesForProject(selectedProject.value.id) : auth.isAdmin.value ? ["ADMIN"] : [],
);
const canDevelop = computed(
  () =>
    selectedProject.value !== null &&
    auth.hasAnyProjectRole(selectedProject.value.id, ["ADMIN", "DEVELOPER"]),
);
const canOperate = computed(
  () =>
    selectedProject.value !== null &&
    auth.hasAnyProjectRole(selectedProject.value.id, ["ADMIN", "OPERATOR"]),
);
const canReadMetadata = computed(
  () =>
    selectedProject.value !== null &&
    auth.hasAnyProjectRole(selectedProject.value.id, ["ADMIN", "DEVELOPER"]),
);
const executionReady = computed(() => {
  const requiredComponents = [
    "worker",
    "runtime",
    "oracle",
    "lifecycle",
    "dispatcher",
    "reconciler",
    "worker_fencing",
    "workspace_volume",
    "egress_policy",
    "keyrings",
    "audit_chain",
  ];
  return (
    props.health?.status === "UP" &&
    requiredComponents.every(
      (component) => props.health?.components[component]?.status === "UP",
    )
  );
});
const pageTitle = computed(() => {
  const titles: Record<PageKey, string> = {
    home: "首页",
    projects: "项目管理",
    datasources: "数据源",
    governance: "治理与授权",
    jobs: "复制任务",
    executions: "运行中心",
    "endpoint-policies": "网络准入策略",
    users: "用户与授权",
    system: "本机运行状态",
  };
  return titles[page.value];
});

async function loadProjects(): Promise<void> {
  projectsLoading.value = true;
  projectsError.value = null;
  try {
    projects.value = (await listProjects()).items;
    if (
      selectedProjectId.value === null ||
      !projects.value.some((project) => project.id === selectedProjectId.value)
    ) {
      selectedProjectId.value =
        projects.value.find((project) => project.status === "ACTIVE")?.id ??
        projects.value[0]?.id ??
        null;
    }
  } catch (caught) {
    projectsError.value = caught;
    projects.value = [];
    selectedProjectId.value = null;
  } finally {
    projectsLoading.value = false;
  }
}

function navigate(nextPage: PageKey): void {
  page.value = nextPage;
  mobileNavOpen.value = false;
  window.location.hash = `/${nextPage}`;
}

function readHash(): void {
  const candidate = window.location.hash.replace(/^#\/?/, "") as PageKey;
  const allowed: PageKey[] = [
    "home",
    "projects",
    "datasources",
    "governance",
    "jobs",
    "executions",
    "endpoint-policies",
    "users",
    "system",
  ];
  if (allowed.includes(candidate)) {
    if (
      ["users", "endpoint-policies"].includes(candidate) &&
      !auth.isAdmin.value
    ) {
      page.value = "home";
    } else if (
      candidate === "governance" &&
      selectedProject.value &&
      !auth.hasAnyProjectRole(selectedProject.value.id, [
          "ADMIN",
          "DEVELOPER",
          "OPERATOR",
          "VIEWER",
        ])
    ) {
      page.value = "home";
    }
    else page.value = candidate;
  }
}

function selectProject(project: Project): void {
  selectedProjectId.value = project.id;
  if (project.status === "ARCHIVED") ElMessage.warning("当前项目已归档，只能查看历史记录。");
  else navigate("home");
}

function requestRun(jobId: string): void {
  runJobId.value = jobId;
  navigate("executions");
}

function openExecution(executionId: string): void {
  requestedExecutionId.value = executionId;
  navigate("executions");
}

function clearRequestedAction(): void {
  runJobId.value = null;
  requestedExecutionId.value = null;
}

function openProfile(): void {
  profileError.value = null;
  passwordForm.current = "";
  passwordForm.next = "";
  passwordForm.confirm = "";
  profileVisible.value = true;
}

async function submitPassword(): Promise<void> {
  if (passwordForm.next.length < 12 || passwordForm.next !== passwordForm.confirm) return;
  passwordLoading.value = true;
  profileError.value = null;
  try {
    await auth.changePassword(passwordForm.current, passwordForm.next);
    ElMessage.success("密码已修改，其他会话已撤销。");
    profileVisible.value = false;
  } catch (caught) {
    profileError.value = caught;
  } finally {
    passwordLoading.value = false;
    passwordForm.current = "";
    passwordForm.next = "";
    passwordForm.confirm = "";
  }
}

async function logout(): Promise<void> {
  await auth.logout();
  window.location.hash = "/home";
}

onMounted(() => {
  readHash();
  window.addEventListener("hashchange", readHash);
  void loadProjects();
});

onBeforeUnmount(() => {
  window.removeEventListener("hashchange", readHash);
});
</script>

<template>
  <div class="app-frame">
    <aside class="sidebar" :class="{ 'sidebar--open': mobileNavOpen }">
      <div class="brand-lockup sidebar__brand">
        <span class="brand-symbol" aria-hidden="true">DX</span>
        <div><strong>DataX Enterprise</strong><span>Studio · 本机版</span></div>
      </div>

      <nav aria-label="主导航">
        <p class="nav-label">项目工作区</p>
        <button :class="{ active: page === 'home' }" @click="navigate('home')"><span>⌂</span>首页</button>
        <button
          :class="{ active: page === 'datasources' }"
          :disabled="!selectedProject"
          @click="navigate('datasources')"
        >
          <span>◫</span>数据源
        </button>
        <button
          v-if="
            selectedProject &&
            auth.hasAnyProjectRole(selectedProject.id, [
              'ADMIN',
              'DEVELOPER',
              'OPERATOR',
              'VIEWER',
            ])
          "
          :class="{ active: page === 'governance' }"
          @click="navigate('governance')"
        >
          <span>◇</span>治理与授权
        </button>
        <button
          :class="{ active: page === 'jobs' }"
          :disabled="!selectedProject"
          @click="navigate('jobs')"
        >
          <span>⇄</span>复制任务
        </button>
        <button
          :class="{ active: page === 'executions' }"
          :disabled="!selectedProject"
          @click="navigate('executions')"
        >
          <span>▶</span>运行中心
        </button>

        <p class="nav-label">管理与状态</p>
        <button :class="{ active: page === 'projects' }" @click="navigate('projects')">
          <span>▦</span>项目管理
        </button>
        <button
          v-if="auth.isAdmin.value"
          :class="{ active: page === 'endpoint-policies' }"
          @click="navigate('endpoint-policies')"
        >
          <span>⌁</span>网络准入策略
        </button>
        <button v-if="auth.isAdmin.value" :class="{ active: page === 'users' }" @click="navigate('users')">
          <span>♙</span>用户与授权
        </button>
        <button :class="{ active: page === 'system' }" @click="navigate('system')">
          <span>●</span>本机运行状态
        </button>
      </nav>

      <div class="sidebar__boundary">
        <strong>Windows 本地工作站</strong>
        <span>仅 127.0.0.1:17860 · 非 HA</span>
      </div>
    </aside>

    <div v-if="mobileNavOpen" class="nav-backdrop" @click="mobileNavOpen = false"></div>

    <div class="workspace">
      <header class="topbar">
        <button class="mobile-menu" aria-label="打开导航" @click="mobileNavOpen = true">☰</button>
        <div class="project-switcher">
          <span>当前项目</span>
          <el-select
            v-model="selectedProjectId"
            placeholder="尚未选择项目"
            :loading="projectsLoading"
            @change="(id: string) => {
              const project = projects.find((item) => item.id === id);
              if (project) selectProject(project);
            }"
          >
            <el-option
              v-for="project in projects"
              :key="project.id"
              :label="`${project.name}${project.status === 'ARCHIVED' ? '（已归档）' : ''}`"
              :value="project.id"
            />
          </el-select>
          <ProblemPanel
            v-if="projectsError && page !== 'projects'"
            class="topbar__project-error"
            :error="projectsError"
            :show-retry="false"
          />
        </div>

        <div class="topbar__right">
          <button class="health-chip" @click="navigate('system')">
            <span
              class="health-dot"
              :class="{
                'health-dot--up': health?.status === 'UP',
                'health-dot--down': health?.status === 'DOWN',
              }"
            ></span>
            {{ health?.status === "UP" ? "本机服务就绪" : health ? "本机服务受阻" : "检查本机服务" }}
          </button>
          <el-dropdown trigger="click">
            <button class="user-menu">
              <span class="avatar">{{ auth.state.user?.display_name.slice(0, 1) }}</span>
              <span><strong>{{ auth.state.user?.display_name }}</strong><small>{{ auth.state.user?.email }}</small></span>
              <span aria-hidden="true">⌄</span>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="openProfile">个人资料与修改密码</el-dropdown-item>
                <el-dropdown-item divided @click="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <main class="main-content" :aria-label="pageTitle">
        <HomePage
          v-if="page === 'home'"
          :project="selectedProject"
          :health="health"
          :health-loading="healthLoading"
          :health-error="healthError"
          @refresh-health="emit('refreshHealth')"
          @open-projects="navigate('projects')"
          @open-execution="openExecution"
        />
        <ProjectsPage
          v-else-if="page === 'projects'"
          :projects="projects"
          :loading="projectsLoading"
          :error="projectsError"
          :is-admin="auth.isAdmin.value"
          :selected-project-id="selectedProjectId"
          @refresh="loadProjects"
          @select="selectProject"
        />
        <DatasourcesPage
          v-else-if="page === 'datasources' && selectedProject"
          :key="selectedProject.id"
          :project-id="selectedProject.id"
          :can-admin="auth.isAdmin.value"
          :can-read-metadata="canReadMetadata"
          :egress-ready="health?.components.egress_policy?.status === 'UP'"
        />
        <GovernancePage
          v-else-if="page === 'governance' && selectedProject"
          :key="selectedProject.id"
          :project="selectedProject"
          :can-admin="auth.isAdmin.value"
          :health="health"
        />
        <JobsPage
          v-else-if="page === 'jobs' && selectedProject"
          :key="selectedProject.id"
          :project-id="selectedProject.id"
          :can-develop="canDevelop"
          :can-operate="canOperate"
          @run="requestRun"
        />
        <ExecutionsPage
          v-else-if="page === 'executions' && selectedProject"
          :key="selectedProject.id"
          :project-id="selectedProject.id"
          :can-operate="canOperate"
          :worker-ready="executionReady"
          :requested-job-id="runJobId"
          :requested-execution-id="requestedExecutionId"
          @request-consumed="clearRequestedAction"
        />
        <UsersPage v-else-if="page === 'users' && auth.isAdmin.value" />
        <EndpointPoliciesPage
          v-else-if="page === 'endpoint-policies' && auth.isAdmin.value"
          :egress-ready="health?.components.egress_policy?.status === 'UP'"
        />
        <div v-else-if="page === 'system'" class="page-stack">
          <header class="page-header">
            <div>
              <p class="kicker">真实组件事实</p>
              <h1>本机运行状态</h1>
              <p>页面只转述后端 readiness；Docker Desktop/WSL2/端口与签名仍由 Windows Launcher 检查。</p>
            </div>
          </header>
          <HealthPanel
            :health="health"
            :loading="healthLoading"
            :error="healthError"
            @refresh="emit('refreshHealth')"
          />
          <section class="content-card">
            <h2>运行边界</h2>
            <dl class="detail-list">
              <div><dt>入口</dt><dd><code>http://127.0.0.1:17860</code></dd></div>
              <div><dt>宿主平台</dt><dd>Windows 11 x64</dd></div>
              <div><dt>运行方式</dt><dd>Docker Desktop + WSL2 中的 Linux 容器</dd></div>
              <div><dt>高可用</dt><dd>不支持，本机停止即不可用</dd></div>
              <div><dt>局域网访问</dt><dd>不支持，仅本机 loopback</dd></div>
              <div><dt>检查时间</dt><dd>{{ formatTime(health?.checked_at) }}</dd></div>
            </dl>
          </section>
        </div>
      </main>
    </div>

    <el-dialog v-model="profileVisible" title="个人资料与修改密码" width="min(620px, 96vw)" destroy-on-close>
      <ProblemPanel v-if="profileError" :error="profileError" :show-retry="false" />
      <dl class="detail-list">
        <div><dt>显示名</dt><dd>{{ auth.state.user?.display_name }}</dd></div>
        <div><dt>登录邮箱</dt><dd>{{ auth.state.user?.email }}</dd></div>
        <div>
          <dt>当前项目角色</dt>
          <dd class="tag-list">
            <StateBadge v-for="role in currentRoles" :key="role" :value="role" />
            <span v-if="!currentRoles.length">—</span>
          </dd>
        </div>
      </dl>
      <el-divider />
      <el-form label-position="top" @submit.prevent="submitPassword">
        <el-form-item label="当前密码" required>
          <el-input v-model="passwordForm.current" type="password" autocomplete="current-password" show-password />
        </el-form-item>
        <el-form-item label="新密码" required>
          <el-input v-model="passwordForm.next" type="password" autocomplete="new-password" show-password />
          <span class="field-help">至少 12 个字符；成功后撤销其他会话。</span>
        </el-form-item>
        <el-form-item label="确认新密码" required>
          <el-input v-model="passwordForm.confirm" type="password" autocomplete="new-password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="profileVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="passwordLoading"
          :disabled="
            !passwordForm.current ||
            passwordForm.next.length < 12 ||
            passwordForm.next !== passwordForm.confirm
          "
          @click="submitPassword"
        >
          修改密码
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
