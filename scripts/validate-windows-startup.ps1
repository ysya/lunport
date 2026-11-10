# CI-only: start the real Development GUI from a synced fixture without touching an existing
# workspace or real credentials. The workflow frontend is a placeholder, so this checks native
# bootstrap/WebView2 creation and shutdown, not React rendering or a user's production machine.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'This isolated startup smoke test is restricted to the disposable GitHub Actions runner.'
}
# Where test-windows.yml has the native tray smoke test export its synced fixture (LUNPORT_TEST_SYNCED_STATE_OUT).
$seed = Join-Path $env:RUNNER_TEMP 'synced-startup.json'
if (-not (Test-Path $seed)) { throw 'The native sync test did not export its fixture.' }
# The Development identity, from the Tauri configuration this GUI is built with. Cargo names the executable after the
# package, which is the main binary name (src-tauri/src/identity.rs).
$production = Get-Content -Raw (Join-Path $PSScriptRoot '..\src-tauri\tauri.conf.json') | ConvertFrom-Json
$development = Get-Content -Raw (Join-Path $PSScriptRoot '..\src-tauri\tauri.dev.conf.json') | ConvertFrom-Json
$title = $development.app.windows[0].title
$profileDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) $development.identifier
$statePath = Join-Path $profileDirectory 'sync-state.json'
if (Test-Path $statePath) { throw 'Refusing to replace an existing Development workspace.' }

$priorConfig = $env:TAURI_CONFIG
try {
    # Cargo-only CI normally embeds the Production config. Explicitly select the same identity
    # as tauri.dev.conf.json for this debug GUI; app_profile verifies it before creating Tauri.
    $env:TAURI_CONFIG = @{
        identifier = $development.identifier
        productName = $development.productName
        app = @{ windows = @(@{ label = 'main'; title = $title; width = 1100; height = 720; visible = $false }) }
    } | ConvertTo-Json -Depth 5 -Compress
    cargo build --locked --features development-profile
    if ($LASTEXITCODE -ne 0) { throw 'Development GUI build failed.' }
} finally {
    $env:TAURI_CONFIG = $priorConfig
}
New-Item -ItemType Directory -Force -Path $profileDirectory | Out-Null
Copy-Item $seed $statePath
$logPath = Join-Path $profileDirectory 'diagnostics\app.log'
$program = (Resolve-Path "target\debug\$($production.mainBinaryName).exe").Path
$stdout = Join-Path $env:RUNNER_TEMP 'lunport-startup.stdout'
$stderr = Join-Path $env:RUNNER_TEMP 'lunport-startup.stderr'
function ConvertFrom-CompleteLogLines {
    param([AllowEmptyString()][string]$LogText)
    # Explicit types also cover an empty file observed between creation and the first append.
    if ([string]::IsNullOrEmpty($LogText)) { return @() }
    [int]$lineEnd = $LogText.LastIndexOf([char]"`n")
    if ($lineEnd -lt 0) { return @() }
    return @($LogText.Substring(0, $lineEnd).Split([char]"`n", [StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { $_ | ConvertFrom-Json })
}
# Exercise empty, incomplete and concurrently appended log records before launching the app.
if (@(ConvertFrom-CompleteLogLines '').Count -ne 0) { throw 'Empty log parsing failed.' }
if (@(ConvertFrom-CompleteLogLines '{"pid":1}').Count -ne 0) { throw 'Incomplete log parsing failed.' }
$probe = @(ConvertFrom-CompleteLogLines ('{"pid":1}' + "`r`n" + '{"pid":2'))
if ($probe.Count -ne 1 -or $probe[0].pid -ne 1) { throw 'Complete-line log parsing failed.' }
$env:RUST_BACKTRACE = '1'
$process = Start-Process $program -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
function Read-ProcessEvents {
    [string]$logText = Get-Content -LiteralPath $logPath -Raw
    return @(ConvertFrom-CompleteLogLines $logText | Where-Object { $_.pid -eq $process.Id })
}
try {
    $ready = $false
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "Development GUI exited during startup ($($process.ExitCode))." }
        if (Test-Path $logPath) {
            $events = Read-ProcessEvents
            if ($events | Where-Object { $_.event -in @('rust_panic', 'gui_build_failed', 'tray_initialization_failed', 'tray_update_failed') }) {
                throw 'Startup diagnostics recorded a native initialization failure.'
            }
            $setupReady = [bool]($events | Where-Object { $_.event -eq 'startup_stage' -and $_.stage -eq 'ready' })
            if ($setupReady -and $process.MainWindowHandle -ne [IntPtr]::Zero -and $process.MainWindowTitle -eq $title) {
                $ready = $true
                break
            }
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { throw 'Development GUI did not expose its real WebView2 window after setup.' }
    # Keep it alive through background status publication and the initial credential failure.
    Start-Sleep -Seconds 3
    $process.Refresh()
    if ($process.HasExited) { throw 'Development GUI crashed after initial background sync.' }
    if (-not $process.CloseMainWindow()) { throw 'Could not request normal GUI shutdown.' }
    if (-not $process.WaitForExit(15000)) { throw 'Development GUI did not close normally.' }
    if ($process.ExitCode -ne 0) { throw "Development GUI exited with $($process.ExitCode)." }
    $events = Read-ProcessEvents
    if (-not ($events | Where-Object { $_.event -eq 'startup_stage' -and $_.stage -eq 'exit' })) {
        throw 'Normal shutdown was not retained in diagnostics.'
    }
    Write-Output 'Actual Windows Development GUI: synced 17-host/Group fixture, WebView2 HWND, background status and normal shutdown passed. No credential fixture or production workspace was used.'
    $events | ConvertTo-Json -Depth 4
} catch {
    # A failed start says why only in what the GUI wrote: its standard error (a Rust panic lands there) and its diagnostics log.
    foreach ($output in @(@('standard error', $stderr), @('standard output', $stdout), @('diagnostics log', $logPath))) {
        Write-Output "--- Development GUI $($output[0])"
        if (Test-Path -LiteralPath $output[1]) { Get-Content -LiteralPath $output[1] -Tail 80 } else { Write-Output '(none)' }
    }
    throw
} finally {
    $process.Refresh()
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
