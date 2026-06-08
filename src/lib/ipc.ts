import { invoke } from "@tauri-apps/api/core";

/**
 * 所有後端呼叫都經這個包裝，之後可在此統一處理錯誤/型別。
 * TODO: 待 ts-rs/tauri-specta 產生 command union 後，把 `cmd` 收斂成已知指令型別，
 *       避免字串拼錯到執行期才爆。
 */
export function tauriInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  return invoke<T>(cmd, args);
}
