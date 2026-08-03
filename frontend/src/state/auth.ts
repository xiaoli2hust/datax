import { computed, reactive, readonly } from "vue";

import {
  changePassword as changePasswordRequest,
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
  restoreSession,
} from "../api/auth";
import type { MeResponse, Role, ScopedRoles, UserSummary } from "../types";

interface AuthState {
  initializing: boolean;
  user: UserSummary | null;
  roleAssignments: ScopedRoles[];
}

const state = reactive<AuthState>({
  initializing: true,
  user: null,
  roleAssignments: [],
});

function setMe(me: MeResponse): void {
  state.user = me.user;
  state.roleAssignments = me.role_assignments;
}

function clear(): void {
  state.user = null;
  state.roleAssignments = [];
}

export function useAuth() {
  const authenticated = computed(() => state.user !== null);
  const mustChangePassword = computed(() => state.user?.must_change_password === true);
  const isAdmin = computed(() =>
    state.roleAssignments.some(
      (assignment) => assignment.scope_type === "ORGANIZATION" && assignment.roles.includes("ADMIN"),
    ),
  );

  async function initialize(): Promise<void> {
    state.initializing = true;
    try {
      await restoreSession();
      setMe(await getCurrentUser());
    } catch {
      clear();
    } finally {
      state.initializing = false;
    }
  }

  async function login(email: string, password: string): Promise<void> {
    const auth = await loginRequest(email, password);
    state.user = auth.user;
    const me = await getCurrentUser();
    setMe(me);
  }

  async function refreshMe(): Promise<void> {
    setMe(await getCurrentUser());
  }

  async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await changePasswordRequest(currentPassword, newPassword);
    await refreshMe();
  }

  async function logout(): Promise<void> {
    try {
      await logoutRequest();
    } finally {
      clear();
    }
  }

  function rolesForProject(projectId: string): Role[] {
    const roles = new Set<Role>();
    if (isAdmin.value) roles.add("ADMIN");
    for (const assignment of state.roleAssignments) {
      if (assignment.scope_type === "PROJECT" && assignment.scope_id === projectId) {
        assignment.roles.forEach((role) => roles.add(role));
      }
    }
    return [...roles];
  }

  function hasAnyProjectRole(projectId: string, required: Role[]): boolean {
    const roles = rolesForProject(projectId);
    return required.some((role) => roles.includes(role));
  }

  return {
    state: readonly(state),
    authenticated,
    mustChangePassword,
    isAdmin,
    initialize,
    login,
    refreshMe,
    changePassword,
    logout,
    rolesForProject,
    hasAnyProjectRole,
  };
}
