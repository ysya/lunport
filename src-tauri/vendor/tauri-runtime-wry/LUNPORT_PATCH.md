# Runtime context ownership patch

This is the published `tauri-runtime-wry` **2.11.2** crate, with its MIT and Apache notices retained. `LUNPORT_PATCH.json` records the crates.io archive checksum and upstream commit. The archive checksum matches the original Cargo.lock entry. Packaging-only cache markers and the dependency's own lockfile are omitted.

Only `src/lib.rs` differs from the published Rust sources. `Context.main_thread` is held in `Arc<DispatcherMainThreadContext<T>>` and initialized with `Arc::new`. Other source files and dependency versions are unchanged.

`AppHandle::clone` clones `WryHandle`, then `Context`. The original derived clone copies `DispatcherMainThreadContext.window_target`. On Windows, that reaches Tao's `Rc<EventLoopRunner<_>>`. Cloning or dropping AppHandles simultaneously on worker threads therefore races a non-atomic native refcount, even though AppHandle is publicly Send + Sync. A corrupted refcount can invalidate the callback during event-loop cleanup or damage heap allocations.

The shared payload makes worker Context clones update only the atomic Arc count. Native access continues through the existing UI-thread checks and dispatch. The runtime retains its context through the event loop; native regression helpers join their workers before returning from the loop, and normal production execution retains the runtime until process exit.

`concurrent_app_handles_preserve_native_event_loop` isolates concurrent handle ownership without a tray, menu, WebView, sync account or credentials. Each process completes 100,000 clones on four workers and verifies normal cleanup. The existing tray/visibility test and actual Development GUI startup remain separate checks. The baseline comparison must show the original runtime failure and repaired behavior before publishing.

Keep this patch until an upstream runtime release makes the same ownership boundary atomic. When removing it, run the handle-only regression, tray stress, actual GUI shutdown and all platform/profile checks against the replacement. Do not replace this with a dependency bump without reviewing the runtime and installer contracts.
