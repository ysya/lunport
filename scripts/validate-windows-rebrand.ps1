# Installs only on an ephemeral GitHub runner. No production GUI or real credentials.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This installer upgrade check runs only on a disposable Windows CI runner.'
}
$scratch = Join-Path $env:RUNNER_TEMP 'lunport-upgrade'
New-Item -ItemType Directory -Force $scratch | Out-Null
$repo = $env:GITHUB_REPOSITORY
$release = (& gh api "repos/$repo/releases/tags/v1.0.0" | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or $release.tag_name -ne 'v1.0.0') { throw 'Cannot read the published upgrade baseline.' }
foreach ($name in @('SSHelter_1.0.0_x64-setup.exe', 'SSHelter_1.0.0_x64_en-US.msi')) {
    & gh release download v1.0.0 --repo $repo --pattern $name --dir $scratch --clobber
    if ($LASTEXITCODE -ne 0) { throw "Cannot download $name" }
    $asset = @($release.assets | Where-Object name -eq $name)
    if ($asset.Count -ne 1) { throw "Cannot identify $name" }
    $hash = (Get-FileHash (Join-Path $scratch $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($asset[0].digest -ne "sha256:$hash") { throw "The published digest does not match $name" }
}
function Run-Installer([string] $Program, [string] $Arguments) {
    $process = Start-Process -FilePath $Program -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "$Program failed with $($process.ExitCode)" }
}
function Msi-Property([string] $Path, [string] $Name) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $view = $database.OpenView("SELECT Value FROM Property WHERE Property = '$Name'")
    [void] $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw "The MSI has no $Name" }
    $value = [string] $record.StringData(1)
    [void] $view.Close()
    return $value
}
$newNsis = @(Get-ChildItem 'src-tauri/target/release/bundle/nsis' -Filter '*-setup.exe')
$newMsi = @(Get-ChildItem 'src-tauri/target/release/bundle/msi' -Filter '*.msi')
if ($newNsis.Count -ne 1 -or $newMsi.Count -ne 1) { throw 'Expected one renamed installer per format.' }
$baselineMsi = Join-Path $scratch 'SSHelter_1.0.0_x64_en-US.msi'
$oldUpgrade = [guid] (Msi-Property $baselineMsi 'UpgradeCode')
$newUpgrade = [guid] (Msi-Property $newMsi[0].FullName 'UpgradeCode')
if ($oldUpgrade -ne $newUpgrade) { throw "MSI UpgradeCode changed: $oldUpgrade / $newUpgrade" }
if ((Msi-Property $newMsi[0].FullName 'ProductName') -ne 'Lunport') { throw 'The MSI is not branded Lunport.' }
Write-Output "Verified the published MSI UpgradeCode is preserved: $newUpgrade"
$sentinel = Join-Path $env:LOCALAPPDATA 'org.homelab.sshelter/rebrand-sentinel.txt'
New-Item -ItemType Directory -Force (Split-Path $sentinel) | Out-Null
Set-Content -LiteralPath $sentinel -Value 'disposable nonsecret upgrade fixture' -NoNewline
$sentinelHash = (Get-FileHash $sentinel -Algorithm SHA256).Hash
function Check-Installed([string] $Directory) {
    $exe = Join-Path $Directory 'sshelter.exe'
    $helper = Join-Path $Directory 'sshelter-cli.exe'
    if (-not (Test-Path $exe) -or -not (Test-Path $helper)) { throw 'Saved executable/helper path was lost.' }
    if ((Get-Item $exe).VersionInfo.ProductName -ne 'Lunport') { throw 'The old path does not contain the renamed app.' }
    $said = (& $helper connect 2>&1 | ForEach-Object { "$_" }) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 2 -or $said -notmatch 'usage: sshelter connect <alias>') { throw 'The existing CLI entry point stopped working.' }
    if ((Get-FileHash $sentinel -Algorithm SHA256).Hash -ne $sentinelHash) { throw 'Existing application data changed.' }
}

# NSIS updater path: same registry identity, executable path and login preference.
$nsisDir = Join-Path $scratch 'original NSIS directory'
Run-Installer (Join-Path $scratch 'SSHelter_1.0.0_x64-setup.exe') ("/S /D=$nsisDir")
$productKey = 'HKCU:\Software\homelab\SSHelter'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SSHelter'
if ((Get-Item $productKey).GetValue('') -ne $nsisDir) { throw 'The old NSIS did not register its install directory.' }
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$loginCommand = '"{0}\sshelter.exe"' -f $nsisDir
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name 'SSHelter' -Value $loginCommand -PropertyType String -Force | Out-Null
Run-Installer $newNsis[0].FullName '/S /UPDATE /NS'
Check-Installed $nsisDir
if ((Get-Item $productKey).GetValue('') -ne $nsisDir) { throw 'NSIS moved the existing installation.' }
if ((Get-ItemProperty $uninstallKey).DisplayName -ne 'Lunport') { throw 'Add/Remove Programs still has the old brand.' }
if ((Get-Item $runKey).GetValue('SSHelter') -ne $loginCommand) { throw 'The update lost the existing login preference.' }
$start = [Environment]::GetFolderPath('Programs')
$desktop = [Environment]::GetFolderPath('Desktop')
foreach ($directory in @($start, $desktop)) {
    if (Test-Path (Join-Path $directory 'SSHelter.lnk')) { throw 'The old NSIS shortcut was left behind.' }
    if (-not (Test-Path (Join-Path $directory 'Lunport.lnk'))) { throw 'The existing shortcut was not renamed.' }
}
Run-Installer (Join-Path $nsisDir 'uninstall.exe') '/S'
if ((Get-Item $runKey).GetValue('SSHelter')) { throw 'Uninstall left a broken login entry.' }
if ((Get-FileHash $sentinel -Algorithm SHA256).Hash -ne $sentinelHash) { throw 'Uninstall removed application data without consent.' }
Remove-Item -LiteralPath $productKey -Recurse -Force

# MSI major upgrade: use its previous registry InstallDir and frozen UpgradeCode.
$msiDir = Join-Path $scratch 'original MSI directory'
Run-Installer 'msiexec.exe' ('/i "{0}" /qn /norestart INSTALLDIR="{1}" /l*v "{2}"' -f $baselineMsi, $msiDir, (Join-Path $scratch 'old-msi.log'))
Run-Installer 'msiexec.exe' ('/i "{0}" /qn /norestart /l*v "{1}"' -f $newMsi[0].FullName, (Join-Path $scratch 'new-msi.log'))
Check-Installed $msiDir
$installer = New-Object -ComObject WindowsInstaller.Installer
if ($installer.ProductState((Msi-Property $baselineMsi 'ProductCode')) -ne -1) { throw 'The previous MSI is still registered.' }
if ((Get-ItemProperty $productKey).InstallDir.TrimEnd('\') -ne $msiDir) { throw 'MSI moved the existing installation.' }
foreach ($directory in @([Environment]::GetFolderPath('CommonPrograms'), $start)) {
    if (Test-Path (Join-Path $directory 'SSHelter/SSHelter.lnk')) { throw 'The old MSI start shortcut was left behind.' }
}
Run-Installer 'msiexec.exe' ('/x "{0}" /qn /norestart' -f (Msi-Property $newMsi[0].FullName 'ProductCode'))
if ((Get-FileHash $sentinel -Algorithm SHA256).Hash -ne $sentinelHash) { throw 'The MSI uninstall removed application data.' }
Write-Output 'NSIS and MSI upgraded SSHelter 1.0.0 to Lunport with saved paths, data and CLI compatibility.'
# The expected CLI usage checks exit with 2. GitHub's pwsh wrapper forwards
# LASTEXITCODE unless the successful validation script returns an explicit 0.
exit 0
