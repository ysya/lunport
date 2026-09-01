import { writeText } from "@tauri-apps/plugin-clipboard-manager";

/** Write text through Tauri's native clipboard implementation. */
export async function copyText(text: string): Promise<void> {
  await writeText(text);
}
