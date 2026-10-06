fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        tauri_build::build();
        return;
    }

    // Windows(MSVC):tauri-build 把 Common Controls v6 的 manifest 放在只連進 app 執行檔的資源檔裡,`cargo test` 的測試執行檔
    // 因此沒有 manifest,載入的是 System32 的 comctl32 5.82(沒有 tao/tauri 用到的 `TaskDialogIndirect`),一啟動就以 0xc0000139
    // (STATUS_ENTRYPOINT_NOT_FOUND)結束,一個測試都沒跑。改由 linker 嵌入同一份 manifest(`windows-app-manifest.xml`,內容同
    // tauri-build 的預設),套用到這個 package 連結的每個產物:app、cdylib 與測試執行檔。
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
    if let Err(error) = tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows)) {
        println!("{error:#}");
        std::process::exit(1);
    }
}
