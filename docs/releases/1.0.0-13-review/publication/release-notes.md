- Serialize native tray creation, lookup, replacement, visibility and handle disposal on the event-loop thread. Initialize the tray before background workers and reuse unchanged menus.
- Update the compatible muda patch to 0.19.3 with its Windows menu lifetime fix.
- Add bounded local startup, sync, GUI failure and Rust panic logs. Add best-effort Windows native exception metadata while preserving normal Windows crash handling. No credentials, sync codes, host records or memory dumps are logged or uploaded.
- Create the Windows main WebView explicitly after native services start, handling ordinary creation errors with logs and a native prompt instead of Tauri Ready-time panic. Background hosts defer the main WebView.
- Open the diagnostic folder from Settings > General > Data > Open logs. Windows GUI initialization errors now show a native diagnostic prompt.

The exact cause of the reported machine-specific Beta 12 startup crash is not yet confirmed. If it continues, retain app.log and native-crash.log from %LOCALAPPDATA%\org.homelab.sshelter\diagnostics, along with the Application Error/WER exception and module details. Existing library, SSH configuration and key approval rules are preserved.
