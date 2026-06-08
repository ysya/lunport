import { invoke } from "@tauri-apps/api/core";

/** 所有後端呼叫都經這個包裝，之後可在此統一處理錯誤/型別。 */
export function tauriInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  return invoke<T>(cmd, args);
}
