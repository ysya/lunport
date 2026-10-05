/**
 * Whether a key event belongs to an IME composition (Chinese, Japanese, Korean input). An Enter that
 * commits a composition must not also submit the form: WebKit reports it as a plain keydown whose
 * `isComposing` is already false, but with the legacy key code 229 (WKWebView, which Tauri uses on macOS),
 * so both are checked. Every key handler that acts on Enter starts with this.
 */
export function isImeKey(e: { nativeEvent: { isComposing: boolean }; keyCode: number }): boolean {
  return e.nativeEvent.isComposing || e.keyCode === 229;
}
