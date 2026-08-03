import type { AuthResponse, MeResponse } from "../types";

import {
  apiGet,
  apiPost,
  clearAccessToken,
  restoreSessionToken,
  setAccessToken,
} from "./client";

export async function login(email: string, password: string): Promise<AuthResponse> {
  const response = await apiPost<AuthResponse>(
    "/auth/login",
    { email: email.trim(), password },
    { allowRefresh: false },
  );
  setAccessToken(response.access_token);
  return response;
}

export async function restoreSession(): Promise<AuthResponse> {
  return restoreSessionToken();
}

export function getCurrentUser(): Promise<MeResponse> {
  return apiGet<MeResponse>("/auth/me");
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await apiPost<null>(
    "/auth/change-password",
    {
      current_password: currentPassword,
      new_password: newPassword,
    },
    { allowRefresh: false },
  );
}

export async function logout(): Promise<void> {
  try {
    await apiPost<null>("/auth/logout", undefined, { allowRefresh: false });
  } finally {
    clearAccessToken();
  }
}
