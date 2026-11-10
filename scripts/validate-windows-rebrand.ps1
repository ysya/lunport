# Upgrades the published 1.14.4 installers to this build's unsigned candidate the way an existing user's machine is upgraded, in
# three phases: the in-app update first (the NSIS installer run with the updater's own flags, /P /R /UPDATE /ARGS, while an AI
# client's 1.14.4 MCP adapter still runs the earlier executable), then the NSIS installer run by hand (/S), then the MSI major
# upgrade. Each phase starts from a 1.14.4 install with application data, two saved credentials (one small enough for Credential
# Manager, one in a DPAPI file), an enabled login item and shortcuts under both names. It checks what the installer leaves (one
# registration under the current identity in the same directory, only the current executables, working shortcuts, nothing of the
# app's moved), what the app's first start moves to the current identity, and what uninstalling removes and keeps. A failing
# check is recorded and the run goes on; every failure is reported at the end.
# Synthetic, nonsecret fixtures only, and only on a disposable GitHub-hosted Windows runner.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This installer upgrade check runs only on a disposable Windows CI runner.'
}
$repository = Split-Path $PSScriptRoot -Parent
$tauri = Get-Content -Raw (Join-Path $repository 'src-tauri/tauri.conf.json') | ConvertFrom-Json
$legacy = (Get-Content -Raw (Join-Path $PSScriptRoot 'legacy-identity.json') | ConvertFrom-Json).production
# Current names come from the Tauri configuration. In Production the installer identity, login item and credential service are
# the product name, and the console helper is the main binary's name with -cli (src-tauri/src/identity.rs).
$new = @{
    AppId = $tauri.identifier
    Product = $tauri.productName
    Publisher = $tauri.bundle.publisher
    UpgradeCode = $tauri.bundle.windows.wix.upgradeCode
    Binary = "$($tauri.mainBinaryName).exe"
    Helper = "$($tauri.mainBinaryName)-cli.exe"
    Usage = "usage: $($tauri.mainBinaryName) connect <alias>"
    LoginItem = $tauri.productName
    CredentialService = $tauri.productName
}
# The 1.14.4 names, from scripts/legacy-identity.json (the only script data that may hold them). The earliest installers also
# named their shortcuts after the installer identity.
$old = @{
    AppId = $legacy.appId
    Installer = $legacy.installerIdentity
    Manufacturer = $legacy.manufacturer
    Binary = "$($legacy.mainBinary).exe"
    Helper = "$($legacy.consoleHelper).exe"
    LoginItem = $legacy.loginItem
    CredentialService = $legacy.credentialService
}
foreach ($names in @($new, $old)) {
    foreach ($key in @($names.Keys)) {
        if (-not $names[$key] -or "$($names[$key])" -match '^(\.exe|-cli\.exe)$') { throw "Missing identity value $key." }
    }
}

$uninstallRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$newUninstall = "$uninstallRoot\$($new.Product)"
$oldUninstall = "$uninstallRoot\$($old.Installer)"
$newProductKey = "HKCU:\Software\$($new.Publisher)\$($new.Product)"
$oldProductKey = "HKCU:\Software\$($old.Manufacturer)\$($old.Installer)"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$approvedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$newRoot = Join-Path $env:LOCALAPPDATA $new.AppId
$oldRoot = Join-Path $env:LOCALAPPDATA $old.AppId
$programs = [Environment]::GetFolderPath('Programs')
$desktop = [Environment]::GetFolderPath('Desktop')
$commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
$commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$pins = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
$productLink = "$($new.Product).lnk"
$legacyLink = "$($old.Installer).lnk"
$shell = New-Object -ComObject WScript.Shell

$scratch = Join-Path $env:RUNNER_TEMP 'lunport-upgrade'
New-Item -ItemType Directory -Force $scratch | Out-Null
$repo = $env:GITHUB_REPOSITORY
$baselineTag = 'v1.14.4'
$baselineNsisName = 'Lunport_1.14.4_x64-setup.exe'
$baselineMsiName = 'Lunport_1.14.4_x64_en-US.msi'
$release = (& gh api "repos/$repo/releases/tags/$baselineTag" | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or $release.tag_name -ne $baselineTag) { throw 'Cannot read the published upgrade baseline.' }
foreach ($name in @($baselineNsisName, $baselineMsiName)) {
    & gh release download $baselineTag --repo $repo --pattern $name --dir $scratch --clobber
    if ($LASTEXITCODE -ne 0) { throw "Cannot download $name" }
    $asset = @($release.assets | Where-Object name -eq $name)
    if ($asset.Count -ne 1) { throw "Cannot identify $name" }
    $hash = (Get-FileHash (Join-Path $scratch $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($asset[0].digest -ne "sha256:$hash") { throw "The published digest does not match $name" }
}
$baselineNsis = Join-Path $scratch $baselineNsisName
$baselineMsi = Join-Path $scratch $baselineMsiName

# Credential Manager and DPAPI, as the app's Windows credential store uses them (windows_credentials.rs), and the AppUserModelID
# a shortcut carries, read the way the installers write it (IShellLink's property store).
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class LunportUpgradeNative
{
    const uint CredTypeGeneric = 1;
    const uint CredPersistEnterprise = 3;
    const int ErrorNotFound = 1168;
    const int CryptProtectUiForbidden = 1;

    [StructLayout(LayoutKind.Sequential)]
    struct Credential
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    class ShellLink
    {
    }

    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IPropertyStore
    {
        void GetCount(out uint count);
        void GetAt(uint index, out PropertyKey key);
        void GetValue(ref PropertyKey key, out PropVariant value);
        void SetValue(ref PropertyKey key, ref PropVariant value);
        void Commit();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PropertyKey
    {
        public Guid FormatId;
        public uint PropertyId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PropVariant
    {
        public ushort Type;
        public ushort Reserved1;
        public ushort Reserved2;
        public ushort Reserved3;
        public IntPtr Value;
        public IntPtr Value2;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
    static extern bool CredWrite(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredDelete(string target, uint type, uint flags);
    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr credentials);
    [DllImport("advapi32.dll")]
    static extern void CredFree(IntPtr buffer);
    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptProtectData(ref DataBlob input, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("ole32.dll")]
    static extern int PropVariantClear(ref PropVariant value);

    static Exception Failure(string operation, int error)
    {
        return new InvalidOperationException(operation + " failed with Win32 error " + error);
    }

    // A generic credential as the keyring crate writes one: target "{account}.{service}", user name the account.
    public static void Write(string target, string user, byte[] secret)
    {
        IntPtr blob = Marshal.AllocHGlobal(Math.Max(secret.Length, 1));
        IntPtr targetName = Marshal.StringToHGlobalUni(target);
        IntPtr userName = Marshal.StringToHGlobalUni(user);
        try
        {
            Marshal.Copy(secret, 0, blob, secret.Length);
            Credential credential = new Credential();
            credential.Type = CredTypeGeneric;
            credential.TargetName = targetName;
            credential.CredentialBlobSize = (uint)secret.Length;
            credential.CredentialBlob = blob;
            credential.Persist = CredPersistEnterprise;
            credential.UserName = userName;
            if (!CredWrite(ref credential, 0)) throw Failure("CredWrite " + target, Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
            Marshal.FreeHGlobal(targetName);
            Marshal.FreeHGlobal(userName);
        }
    }

    // The stored bytes, or null when there is no such credential.
    public static byte[] Read(string target)
    {
        IntPtr pointer;
        if (!CredRead(target, CredTypeGeneric, 0, out pointer))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound) return null;
            throw Failure("CredRead " + target, error);
        }
        try
        {
            Credential credential = Marshal.PtrToStructure<Credential>(pointer);
            byte[] secret = new byte[credential.CredentialBlobSize];
            if (secret.Length > 0) Marshal.Copy(credential.CredentialBlob, secret, 0, secret.Length);
            return secret;
        }
        finally
        {
            CredFree(pointer);
        }
    }

    public static void Delete(string target)
    {
        if (!CredDelete(target, CredTypeGeneric, 0))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorNotFound) throw Failure("CredDelete " + target, error);
        }
    }

    // Every credential target of the current user.
    public static string[] Targets()
    {
        uint count;
        IntPtr list;
        if (!CredEnumerate(null, 0, out count, out list))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound) return new string[0];
            throw Failure("CredEnumerate", error);
        }
        try
        {
            List<string> targets = new List<string>();
            for (int index = 0; index < count; index++)
            {
                Credential credential = Marshal.PtrToStructure<Credential>(Marshal.ReadIntPtr(list, index * IntPtr.Size));
                targets.Add(Marshal.PtrToStringUni(credential.TargetName));
            }
            return targets.ToArray();
        }
        finally
        {
            CredFree(list);
        }
    }

    static byte[] Dpapi(byte[] data, byte[] entropy, bool decrypt)
    {
        DataBlob input = new DataBlob();
        DataBlob extra = new DataBlob();
        input.Size = data.Length;
        input.Data = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
        extra.Size = entropy.Length;
        extra.Data = Marshal.AllocHGlobal(Math.Max(entropy.Length, 1));
        try
        {
            Marshal.Copy(data, 0, input.Data, data.Length);
            Marshal.Copy(entropy, 0, extra.Data, entropy.Length);
            DataBlob output;
            bool done = decrypt
                ? CryptUnprotectData(ref input, IntPtr.Zero, ref extra, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out output)
                : CryptProtectData(ref input, IntPtr.Zero, ref extra, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out output);
            if (!done) throw Failure(decrypt ? "CryptUnprotectData" : "CryptProtectData", Marshal.GetLastWin32Error());
            try
            {
                byte[] result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, output.Size);
                return result;
            }
            finally
            {
                LocalFree(output.Data);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input.Data);
            Marshal.FreeHGlobal(extra.Data);
        }
    }

    // DPAPI CurrentUser, no prompts.
    public static byte[] Protect(byte[] data, byte[] entropy) { return Dpapi(data, entropy, false); }
    public static byte[] Unprotect(byte[] data, byte[] entropy) { return Dpapi(data, entropy, true); }

    // The AppUserModelID (PKEY_AppUserModel_ID) a .lnk carries, or null when it has none.
    public static string AppUserModelId(string shortcut)
    {
        object link = new ShellLink();
        try
        {
            ((System.Runtime.InteropServices.ComTypes.IPersistFile)link).Load(shortcut, 0);
            PropertyKey key = new PropertyKey();
            key.FormatId = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
            key.PropertyId = 5;
            PropVariant value;
            ((IPropertyStore)link).GetValue(ref key, out value);
            try
            {
                // VT_LPWSTR, or VT_BSTR as the NSIS macro writes it; anything else, VT_EMPTY included, is no ID.
                return value.Type == 31 || value.Type == 8 ? Marshal.PtrToStringUni(value.Value) : null;
            }
            finally
            {
                PropVariantClear(ref value);
            }
        }
        finally
        {
            Marshal.ReleaseComObject(link);
        }
    }
}
'@

# Values longer than 2,560 bytes as UTF-16 are kept in a DPAPI file; the credential holds this 81-byte reference
# (credential_blob.rs): magic, 32 bytes of entropy, the SHA-256 of the ciphertext, plaintext and ciphertext lengths, a zero.
$magic = [Text.Encoding]::ASCII.GetBytes('LPCRD001')
$sentinelName = 'upgrade-sentinel.txt'
# Saved passwords by account: one Credential Manager holds, and one too large for it, kept in a DPAPI file.
$credentials = [ordered]@{
    'host:acme-upgrade-short' = 'synthetic upgrade fixture, short'
    'host:acme-upgrade-large' = 'synthetic upgrade fixture, not a secret. ' * 120
}
$script:sentinelHash = $null
$script:loginCommand = $null
$script:adapter = $null
$script:msiDesktopLink = $null
$script:msiStartLink = $null
$script:msiLegacyLinks = @()
$failures = [Collections.Generic.List[string]]::new()

function ConvertTo-HexText([byte[]] $Bytes) { [Convert]::ToHexString($Bytes).ToLowerInvariant() }

# Runs one check of a phase. A failure is recorded and the run goes on, so each phase reports installer, first-start and
# uninstall results on their own. Returns whether the check passed.
function Test-Stage([string] $Phase, [string] $Stage, [scriptblock] $Body) {
    Write-Host "== $Phase / $Stage"
    try {
        & $Body | Out-Host
        Write-Host "PASS $Phase / $Stage"
        return $true
    } catch {
        $failures.Add("$Phase / ${Stage}: $($_.Exception.Message)")
        Write-Host "FAIL $Phase / ${Stage}: $($_.Exception.Message)"
        return $false
    }
}

# The DPAPI entropy: the magic, the reference's entropy, then service and account, each after its UTF-8 length.
function Get-CredentialBinding([byte[]] $Entropy, [string] $Service, [string] $Account) {
    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange($magic)
    $bytes.AddRange($Entropy)
    foreach ($field in @($Service, $Account)) {
        $text = [Text.Encoding]::UTF8.GetBytes($field)
        $bytes.AddRange([BitConverter]::GetBytes([uint32] $text.Length))
        $bytes.AddRange($text)
    }
    return , $bytes.ToArray()
}

# The app keeps DPAPI files in an owner-only folder and refuses others (sync/central_files_windows.rs).
function Set-OwnerOnly([string] $Path, [switch] $Directory) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $inherit = if ($Directory) { 'OICI' } else { '' }
    $security = Get-Acl -LiteralPath $Path
    $security.SetSecurityDescriptorSddlForm("D:P(A;$inherit;FA;;;$sid)", [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $security
}

# Saves a credential under Service as that version of the app does.
function Set-AppCredential([string] $Service, [string] $Account, [string] $Secret, [string] $Root) {
    $target = "$Account.$Service"
    if ($Secret.Length -le 1280) {
        [LunportUpgradeNative]::Write($target, $Account, [Text.Encoding]::Unicode.GetBytes($Secret))
        return
    }
    $entropy = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $plain = [Text.Encoding]::UTF8.GetBytes($Secret)
    $cipher = [LunportUpgradeNative]::Protect($plain, (Get-CredentialBinding $entropy $Service $Account))
    $digest = [Security.Cryptography.SHA256]::HashData($cipher)
    $folder = Join-Path $Root 'protected-credentials'
    New-Item -ItemType Directory -Force $folder | Out-Null
    Set-OwnerOnly $folder -Directory
    $file = Join-Path $folder "$(ConvertTo-HexText $digest).cred"
    [IO.File]::WriteAllBytes($file, $cipher)
    Set-OwnerOnly $file
    $reference = [Collections.Generic.List[byte]]::new()
    $reference.AddRange($magic)
    $reference.AddRange($entropy)
    $reference.AddRange($digest)
    $reference.AddRange([BitConverter]::GetBytes([uint32] $plain.Length))
    $reference.AddRange([BitConverter]::GetBytes([uint32] $cipher.Length))
    $reference.Add([byte] 0)
    [LunportUpgradeNative]::Write($target, $Account, $reference.ToArray())
}

# Reads a credential saved under Service as the app reads it, or $null when there is none.
function Get-AppCredential([string] $Service, [string] $Account, [string] $Root) {
    $raw = [LunportUpgradeNative]::Read("$Account.$Service")
    if ($null -eq $raw) { return $null }
    if ($raw.Length % 2 -eq 0) { return [Text.Encoding]::Unicode.GetString($raw) }
    if ($raw.Length -ne 81 -or (ConvertTo-HexText ([byte[]] $raw[0..7])) -ne (ConvertTo-HexText $magic) -or $raw[80] -ne 0) {
        throw "$Account under $Service is neither a password nor a protected-file reference."
    }
    $digest = [byte[]] $raw[40..71]
    $file = Join-Path $Root "protected-credentials\$(ConvertTo-HexText $digest).cred"
    if (-not (Test-Path -LiteralPath $file)) { throw "$Account under $Service refers to $file, which does not exist." }
    $cipher = [IO.File]::ReadAllBytes($file)
    if ($cipher.Length -ne [BitConverter]::ToUInt32($raw, 76) -or (ConvertTo-HexText ([Security.Cryptography.SHA256]::HashData($cipher))) -ne (ConvertTo-HexText $digest)) {
        throw "$file is not the ciphertext $Account under $Service refers to."
    }
    $plain = [LunportUpgradeNative]::Unprotect($cipher, (Get-CredentialBinding ([byte[]] $raw[8..39]) $Service $Account))
    if ($plain.Length -ne [BitConverter]::ToUInt32($raw, 72)) { throw "$Account under $Service has the wrong length." }
    return [Text.Encoding]::UTF8.GetString($plain)
}

function Get-ServiceTargets([string] $Service) {
    @([LunportUpgradeNative]::Targets() | Where-Object { $_.EndsWith(".$Service", [StringComparison]::Ordinal) })
}

# Runs an installer to its end. By default this waits for every process it starts (an NSIS uninstaller reruns itself from a
# temporary copy); -OnlyProcess waits for the installer alone, when it starts the app on its way out (/R).
function Run-Installer([string] $Program, [string] $Arguments, [switch] $OnlyProcess) {
    Write-Output "Running $Program $Arguments"
    if ($OnlyProcess) {
        $process = Start-Process -FilePath $Program -ArgumentList $Arguments -PassThru
        # Holding the handle keeps the exit code readable after the process ends.
        $null = $process.Handle
        $process.WaitForExit()
    } else {
        $process = Start-Process -FilePath $Program -ArgumentList $Arguments -Wait -PassThru
    }
    if ($process.ExitCode -notin @(0, 3010)) { throw "$Program failed with $($process.ExitCode)" }
}

# The Windows Installer and WScript.Shell objects are called late-bound (Type.InvokeMember), as Microsoft's PowerShell samples call
# them: read through PowerShell's own COM binding, the Windows Installer's Record.StringData gave pointer-like numbers for MSI fields.
function Invoke-Com($Object, [string] $Member, [Reflection.BindingFlags] $Kind, [object[]] $Arguments) {
    , ($Object.GetType().InvokeMember($Member, $Kind, $null, $Object, $Arguments))
}

# What a COM call returned, with its type when it is not text, for the error of a read that returned something else.
function Format-ComValue($Value) {
    if ($Value -is [string]) { "'$Value'" } elseif ($null -eq $Value) { '<null>' } else { "[$($Value.GetType().FullName)] $Value" }
}

function Msi-Property([string] $Path, [string] $Name) {
    $database = Invoke-Com (New-Object -ComObject WindowsInstaller.Installer) OpenDatabase InvokeMethod @($Path, 0)
    $view = Invoke-Com $database OpenView InvokeMethod @("SELECT Value FROM Property WHERE Property = '$Name'")
    [void] (Invoke-Com $view Execute InvokeMethod $null)
    $record = Invoke-Com $view Fetch InvokeMethod $null
    if ($null -eq $record) { throw "The MSI has no $Name" }
    $value = Invoke-Com $record StringData GetProperty @(1)
    [void] (Invoke-Com $view Close InvokeMethod $null)
    if ($value -isnot [string]) { throw "The $Name of $Path read as $(Format-ComValue $value)." }
    return $value
}

# The install state of the product with this code: -1 when it is neither installed nor advertised, 5 when it is installed.
function Msi-ProductState([string] $Code) {
    $state = Invoke-Com (New-Object -ComObject WindowsInstaller.Installer) ProductState GetProperty @($Code)
    if ($state -isnot [int]) { throw "The install state of $Code read as $(Format-ComValue $state)." }
    return $state
}

function Remove-Tree([string] $Path) {
    for ($attempt = 1; Test-Path -LiteralPath $Path; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } catch {
            # WebView2 helpers can hold files in a data root for a moment after the app exits.
            if ($attempt -ge 30) { throw }
            Start-Sleep -Seconds 1
        }
    }
}

function Get-ShortcutTarget([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $target = Invoke-Com (Invoke-Com $shell CreateShortcut InvokeMethod @($Path)) TargetPath GetProperty $null
    if ($target -isnot [string]) { throw "The target of $Path read as $(Format-ComValue $target)." }
    return $target
}

# The first of Paths that exists: an installer's per-machine and per-user folders differ by install scope.
function Find-Shortcut([string[]] $Paths) {
    $found = @($Paths | Where-Object { Test-Path -LiteralPath $_ })
    if ($found.Count -eq 0) { throw "None of these shortcuts exists: $($Paths -join ', ')" }
    return $found[0]
}

# A shortcut starts Target and carries the AppUserModelID Model; an empty Model skips that check (the MSI's desktop shortcut
# has none).
function Assert-Shortcut([string] $Path, [string] $Target, [string] $Model) {
    $actual = Get-ShortcutTarget $Path
    if ($actual -ne $Target) { throw "$Path starts '$actual', not '$Target'." }
    if ($Model) { Assert-ShortcutModel $Path $Model }
    Write-Output "$Path starts $actual$(if ($Model) { " with AppUserModelID $Model" })."
}

# The AppUserModelID a shortcut carries, read from its property store.
function Assert-ShortcutModel([string] $Path, [string] $Model) {
    $id = [LunportUpgradeNative]::AppUserModelId($Path)
    if ($id -ne $Model) { throw "$Path has AppUserModelID '$id', not '$Model'." }
}

# Uninstall entries of this product under either identity, in every registry view an installer writes to.
function Get-InstallEntries {
    $names = @($new.Product, $old.Installer)
    $roots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $root) {
            $displayName = $key.GetValue('DisplayName')
            if ($key.PSChildName -in $names -or $displayName -in $names) {
                [pscustomobject]@{ Key = $key.Name; DisplayName = $displayName; Publisher = $key.GetValue('Publisher'); Version = $key.GetValue('DisplayVersion') }
            }
        }
    }
}

function Assert-OneRegistration {
    $entries = @(Get-InstallEntries)
    $entries | Format-Table -AutoSize | Out-Host
    if ($entries.Count -ne 1) { throw "Expected one install entry for $($new.Product), found $($entries.Count)." }
    if ($entries[0].DisplayName -ne $new.Product -or $entries[0].Publisher -ne $new.Publisher) {
        throw "The install entry is '$($entries[0].DisplayName)' by '$($entries[0].Publisher)', not '$($new.Product)' by '$($new.Publisher)'."
    }
}

function Show-Diagnostics {
    foreach ($root in @($oldRoot, $newRoot)) {
        if (-not (Test-Path -LiteralPath $root)) { Write-Output "$root does not exist."; continue }
        Write-Output "$root holds:"
        Get-ChildItem -LiteralPath $root -Recurse -Force -Depth 2 | Where-Object FullName -notmatch 'EBWebView' |
            ForEach-Object { Write-Output "  $($_.FullName.Substring($root.Length + 1))" }
        $log = Join-Path $root 'diagnostics\app.log'
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 40 }
    }
    Write-Output "Credential targets: $((@(Get-ServiceTargets $new.CredentialService) + @(Get-ServiceTargets $old.CredentialService)) -join ', ')"
    Get-ItemProperty -LiteralPath $runKey | Format-List | Out-Host
}

# The running instances of Program, found by their executable path whatever account token they run with.
function Get-AppProcesses([string] $Program) {
    $name = Split-Path $Program -Leaf
    @(Get-CimInstance Win32_Process -Filter "Name = '$name'" | Where-Object { $_.ExecutablePath -eq $Program } |
        ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
}

function Stop-App([string] $Program) {
    foreach ($process in Get-AppProcesses $Program) {
        [void] $process.CloseMainWindow()
        if (-not $process.WaitForExit(10000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            [void] $process.WaitForExit(10000)
        }
    }
}

# Leaves no installation, data, credential, login entry or shortcut of either identity behind, so that each phase starts clean.
function Reset-Machine {
    foreach ($binary in @($new.Binary, $old.Binary)) {
        Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($binary)) -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    $related = Invoke-Com (New-Object -ComObject WindowsInstaller.Installer) RelatedProducts GetProperty @(([guid] $new.UpgradeCode).ToString('B').ToUpperInvariant())
    # StringList.Item counts from 0.
    $count = Invoke-Com $related Count GetProperty $null
    $products = @(for ($index = 0; $index -lt $count; $index++) { Invoke-Com $related Item GetProperty @($index) })
    if (@($products | Where-Object { $_ -isnot [string] -or $_ -notmatch '^\{[0-9A-F-]{36}\}$' }).Count -ne 0) {
        throw "The products related to $($new.UpgradeCode) read as $(@($products | ForEach-Object { Format-ComValue $_ }) -join ', ')."
    }
    foreach ($product in $products) {
        Start-Process -FilePath msiexec.exe -ArgumentList "/x $product /qn /norestart" -Wait | Out-Null
    }
    foreach ($service in @($new.CredentialService, $old.CredentialService)) {
        foreach ($target in Get-ServiceTargets $service) { [LunportUpgradeNative]::Delete($target) }
    }
    foreach ($path in @($newRoot, $oldRoot, (Join-Path $env:APPDATA $new.AppId), (Join-Path $env:APPDATA $old.AppId))) { Remove-Tree $path }
    foreach ($name in @($new.LoginItem, $old.LoginItem)) {
        Remove-ItemProperty -LiteralPath $runKey -Name $name -ErrorAction SilentlyContinue
        if (Test-Path $approvedKey) { Remove-ItemProperty -LiteralPath $approvedKey -Name $name -ErrorAction SilentlyContinue }
    }
    foreach ($key in @($newProductKey, $oldProductKey, $newUninstall, $oldUninstall)) {
        if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force }
    }
    foreach ($folder in @($programs, $desktop, $pins, $commonDesktop)) {
        foreach ($name in @($productLink, $legacyLink)) { Remove-Item -LiteralPath (Join-Path $folder $name) -Force -ErrorAction SilentlyContinue }
    }
    foreach ($folder in @($programs, $commonPrograms)) {
        foreach ($name in @($new.Product, $old.Installer)) { Remove-Tree (Join-Path $folder $name) }
    }
    if (-not (Test-Path $runKey)) { New-Item -Path $runKey | Out-Null }
    $left = @(Get-InstallEntries)
    if ($left.Count -ne 0) { throw "An installation was left behind: $($left.Key -join ', ')" }
}

# What 1.14.4 left on a machine where it was used: data in its root, two saved credentials and the login item it registers.
function New-LegacyState([string] $Directory) {
    New-Item -ItemType Directory -Force $oldRoot | Out-Null
    $sentinel = Join-Path $oldRoot $sentinelName
    Set-Content -LiteralPath $sentinel -Value 'disposable nonsecret upgrade fixture' -NoNewline
    $script:sentinelHash = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
    foreach ($account in $credentials.Keys) {
        Set-AppCredential $old.CredentialService $account $credentials[$account] $oldRoot
        $protected = [LunportUpgradeNative]::Read("$account.$($old.CredentialService)").Length -eq 81
        if ($protected -ne ($credentials[$account].Length -gt 1280)) { throw "The $account fixture is not stored the way its size requires." }
        if ((Get-AppCredential $old.CredentialService $account $oldRoot) -cne $credentials[$account]) { throw "The $account fixture does not read back." }
    }
    # As the autostart plugin (auto-launch) writes an enabled entry: the unquoted path and a space, then Task Manager's state.
    $script:loginCommand = '{0} ' -f (Join-Path $Directory $old.Binary)
    New-ItemProperty -LiteralPath $runKey -Name $old.LoginItem -Value $script:loginCommand -PropertyType String -Force | Out-Null
    if (Test-Path $approvedKey) {
        New-ItemProperty -LiteralPath $approvedKey -Name $old.LoginItem -Value ([byte[]] (2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -PropertyType Binary -Force | Out-Null
    }
}

# An AI client's MCP adapter from 1.14.4: the earlier executable with --mcp, idle on a stdin that stays open (it reads requests
# and touches nothing else until one comes).
function Start-LegacyAdapter([string] $Program) {
    $start = [Diagnostics.ProcessStartInfo]::new($Program, '--mcp')
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    Start-Sleep -Seconds 2
    if ($process.HasExited) { throw "The earlier MCP adapter exited at once with $($process.ExitCode)." }
    Write-Host "Started the earlier MCP adapter (pid $($process.Id)): $Program --mcp"
    return $process
}

# The installer moves nothing that belongs to the app: that waits for the app's first start.
function Assert-DataUntouched {
    if (Test-Path -LiteralPath $newRoot) { throw "The installer created $newRoot before the app could move the earlier data." }
    if ((Get-FileHash -LiteralPath (Join-Path $oldRoot $sentinelName) -Algorithm SHA256).Hash -ne $script:sentinelHash) { throw 'The installer changed application data.' }
    foreach ($account in $credentials.Keys) {
        if ((Get-AppCredential $old.CredentialService $account $oldRoot) -cne $credentials[$account]) { throw "The installer changed the saved $account." }
    }
    if ((Get-Item -LiteralPath $runKey).GetValue($old.LoginItem) -ne $script:loginCommand) { throw 'The installer changed the login entry the app moves.' }
}

function Assert-Executables([string] $Directory) {
    Get-ChildItem -LiteralPath $Directory -Force | Select-Object Name, Length | Format-Table | Out-Host
    foreach ($name in @($new.Binary, $new.Helper)) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name))) { throw "$name is missing from $Directory." }
    }
    foreach ($name in @($old.Binary, $old.Helper)) {
        if (Test-Path -LiteralPath (Join-Path $Directory $name)) { throw "The earlier $name is still in $Directory." }
    }
    if ((Get-Item -LiteralPath (Join-Path $Directory $new.Binary)).VersionInfo.ProductName -ne $new.Product) { throw "$($new.Binary) is not $($new.Product)." }
    if (Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($old.Binary)) -ErrorAction SilentlyContinue) { throw "The earlier $($old.Binary) is still running." }
}

function Assert-ConsoleHelper([string] $Directory) {
    $helper = Join-Path $Directory $new.Helper
    $said = (& $helper connect 2>&1 | ForEach-Object { "$_" }) -join [Environment]::NewLine
    $code = $LASTEXITCODE
    if ($code -ne 2 -or -not $said.Contains($new.Usage)) { throw "$helper connect exited with $code and did not print '$($new.Usage)': $said" }
}

# What the app's first start has not moved to the current identity yet.
function Get-PendingMoves {
    $pending = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $oldRoot) { $pending.Add("$oldRoot still exists") }
    if (-not (Test-Path -LiteralPath (Join-Path $newRoot $sentinelName))) { $pending.Add("the data is not in $newRoot") }
    foreach ($account in $credentials.Keys) {
        if ($null -ne [LunportUpgradeNative]::Read("$account.$($old.CredentialService)")) { $pending.Add("$account is still saved under $($old.CredentialService)") }
        if ($null -eq [LunportUpgradeNative]::Read("$account.$($new.CredentialService)")) { $pending.Add("$account is not saved under $($new.CredentialService)") }
    }
    $run = Get-Item -LiteralPath $runKey
    if ($null -ne $run.GetValue($old.LoginItem)) { $pending.Add("the login entry $($old.LoginItem) is still registered") }
    if ($null -eq $run.GetValue($new.LoginItem)) { $pending.Add("the login entry $($new.LoginItem) is missing") }
    return , $pending
}

# Waits for the upgraded app's first start to move data, credentials and the login entry, then closes it. With
# -StartedByInstaller the installer has started it (the updater's /R runs it through nsis_tauri_utils::RunAsUser); when that
# instance does not appear, the app is started here so the first-start checks still run.
function Invoke-FirstStart([string] $Directory, [switch] $StartedByInstaller) {
    $program = Join-Path $Directory $new.Binary
    if ($StartedByInstaller) {
        $deadline = (Get-Date).AddSeconds(30)
        while (@(Get-AppProcesses $program).Count -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if (@(Get-AppProcesses $program).Count -ne 0) {
            Write-Output "The installer started $program, as the updater's /R does."
        } else {
            Write-Output "The installer did not start $program within 30 s (RunAsUser on this runner); starting it here."
            [void] (Start-Process -FilePath $program -PassThru)
        }
    } else {
        Write-Output "Starting $program for its first start"
        [void] (Start-Process -FilePath $program -PassThru)
    }
    try {
        $deadline = (Get-Date).AddSeconds(120)
        while ($true) {
            $pending = Get-PendingMoves
            if ($pending.Count -eq 0) { break }
            if (@(Get-AppProcesses $program).Count -eq 0) { Show-Diagnostics; throw "The upgraded app is no longer running while $($pending -join '; ')." }
            if ((Get-Date) -gt $deadline) { Show-Diagnostics; throw "The upgraded app's first start did not finish moving: $($pending -join '; ')." }
            Start-Sleep -Milliseconds 500
        }
        Write-Output 'The first start moved data, credentials and the login entry to the current identity.'
    } finally {
        Stop-App $program
    }
}

function Assert-Moved([string] $Directory) {
    if ((Get-FileHash -LiteralPath (Join-Path $newRoot $sentinelName) -Algorithm SHA256).Hash -ne $script:sentinelHash) { throw 'Application data changed while it moved.' }
    foreach ($account in $credentials.Keys) {
        if ((Get-AppCredential $new.CredentialService $account $newRoot) -cne $credentials[$account]) { throw "The saved $account did not keep its value under $($new.CredentialService)." }
    }
    $left = @(Get-ServiceTargets $old.CredentialService)
    if ($left.Count -ne 0) { throw "Credentials are still saved under $($old.CredentialService): $($left -join ', ')" }
    $command = (Get-Item -LiteralPath $runKey).GetValue($new.LoginItem)
    $program = Join-Path $Directory $new.Binary
    if ($command.IndexOf($program, [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw "The login entry starts '$command', not $program." }
    # The app reads Task Manager's state too: a value there must not disable the moved entry.
    if (Test-Path $approvedKey) {
        $approved = (Get-Item -LiteralPath $approvedKey).GetValue($new.LoginItem)
        if ($approved -and @($approved[-8..-1] | Where-Object { $_ -ne 0 }).Count -ne 0) { throw 'The moved login entry is disabled.' }
    }
}

# After an uninstall the data is still there, in whichever root it is: moved by a first start or not.
function Assert-DataKept {
    $copies = @(@($newRoot, $oldRoot) | ForEach-Object { Join-Path $_ $sentinelName } | Where-Object { Test-Path -LiteralPath $_ })
    if ($copies.Count -eq 0) { throw 'Uninstall removed application data without consent.' }
    foreach ($copy in $copies) {
        if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne $script:sentinelHash) { throw "Uninstall changed application data ($copy)." }
    }
}

function Test-NsisUpgrade([string] $Phase, [string] $Arguments, [switch] $Updater) {
    $directory = Join-Path $scratch "$Phase directory"
    $oldProgram = Join-Path $directory $old.Binary
    $program = Join-Path $directory $new.Binary
    $script:adapter = $null
    $ready = Test-Stage $Phase 'install 1.14.4 with data, credentials, a login entry and shortcuts under both names' {
        Run-Installer $baselineNsis "/S /D=$directory"
        if (-not (Test-Path -LiteralPath $oldUninstall)) { throw 'The baseline NSIS did not register its uninstall entry.' }
        if ((Get-Item -LiteralPath $oldProductKey).GetValue('') -ne $directory) { throw 'The baseline NSIS did not register its install directory.' }
        foreach ($folder in @($programs, $desktop)) { Assert-Shortcut (Join-Path $folder $productLink) $oldProgram '' }
        New-LegacyState $directory
        # Shortcuts under the name from before the product rename: a Start menu one beside the current one, and the desktop one
        # renamed. Taskbar pins under both names (copies of the Start menu shortcut).
        Copy-Item -LiteralPath (Join-Path $programs $productLink) -Destination (Join-Path $programs $legacyLink)
        Rename-Item -LiteralPath (Join-Path $desktop $productLink) -NewName $legacyLink
        New-Item -ItemType Directory -Force $pins | Out-Null
        foreach ($name in @($productLink, $legacyLink)) { Copy-Item -LiteralPath (Join-Path $programs $productLink) -Destination (Join-Path $pins $name) -Force }
        if ($Updater) { $script:adapter = Start-LegacyAdapter $oldProgram }
    }
    if ($ready) {
        # Shows the AppUserModelID read works on a known value (1.14.4 used its bundle id), so the checks after the upgrade mean
        # something; its own stage, so a failing read does not stop the phase.
        [void] (Test-Stage $Phase '1.14.4 shortcuts carry its AppUserModelID' {
            foreach ($link in @((Join-Path $programs $productLink), (Join-Path $desktop $legacyLink))) { Assert-ShortcutModel $link $old.AppId }
        })
    }
    $upgraded = $ready -and (Test-Stage $Phase "upgrade with $Arguments" { Run-Installer $candidateNsis $Arguments -OnlyProcess:$Updater })
    if ($upgraded) {
        if ($Updater) {
            [void] (Test-Stage $Phase 'the running earlier executable was stopped and removed' {
                if (-not $script:adapter.WaitForExit(10000)) { throw "The earlier MCP adapter (pid $($script:adapter.Id)) still runs." }
                if (Test-Path -LiteralPath $oldProgram) { throw "$oldProgram is still there." }
            })
        }
        [void] (Test-Stage $Phase 'one registration in the same directory' {
            Assert-OneRegistration
            if (Test-Path -LiteralPath $oldUninstall) { throw 'The earlier uninstall entry is still registered.' }
            $entry = Get-Item -LiteralPath $newUninstall
            if ($entry.GetValue('InstallLocation') -ne ('"{0}"' -f $directory)) { throw "The uninstall entry points at $($entry.GetValue('InstallLocation'))." }
            if ($entry.GetValue('MainBinaryName') -ne $new.Binary) { throw "The uninstall entry records $($entry.GetValue('MainBinaryName'))." }
            if ((Get-Item -LiteralPath $newProductKey).GetValue('') -ne $directory) { throw 'NSIS moved the existing installation.' }
            if ((Test-Path -LiteralPath $oldProductKey) -and $null -ne (Get-Item -LiteralPath $oldProductKey).GetValue('')) { throw 'The earlier install directory is still registered.' }
        })
        [void] (Test-Stage $Phase 'only the current executables' { Assert-Executables $directory })
        [void] (Test-Stage $Phase 'shortcuts and taskbar pins start the current executable' {
            foreach ($folder in @($programs, $desktop)) {
                Assert-Shortcut (Join-Path $folder $productLink) $program $new.AppId
                if (Test-Path -LiteralPath (Join-Path $folder $legacyLink)) { throw "$legacyLink was left in $folder." }
            }
            foreach ($name in @($productLink, $legacyLink)) { Assert-Shortcut (Join-Path $pins $name) $program $new.AppId }
        })
        # With /R the app starts as the installer ends, so only the phases without it can see the untouched state.
        if (-not $Updater) {
            [void] (Test-Stage $Phase 'data, credentials and login entry left for the app' { Assert-DataUntouched })
        }
        [void] (Test-Stage $Phase 'first start moves data, credentials and the login entry' {
            Invoke-FirstStart $directory -StartedByInstaller:$Updater
            Assert-Moved $directory
        })
        [void] (Test-Stage $Phase 'console helper prints the usage' { Assert-ConsoleHelper $directory })
        [void] (Test-Stage $Phase 'uninstall removes the installation and keeps the data' {
            Stop-App $program
            # The login entry under both names goes; an earlier one the app did not move is added back for that.
            New-ItemProperty -LiteralPath $runKey -Name $old.LoginItem -Value $script:loginCommand -PropertyType String -Force | Out-Null
            Run-Installer (Join-Path $directory 'uninstall.exe') '/S'
            if (@(Get-InstallEntries).Count -ne 0) { throw 'The uninstaller left an install entry.' }
            foreach ($name in @($new.LoginItem, $old.LoginItem)) {
                if ($null -ne (Get-Item -LiteralPath $runKey).GetValue($name)) { throw "Uninstall left the login entry $name." }
            }
            if (Test-Path -LiteralPath $directory) { throw "Uninstall left $directory with $((Get-ChildItem -LiteralPath $directory -Force).Name -join ', ')." }
            foreach ($folder in @($programs, $desktop)) {
                if (Test-Path -LiteralPath (Join-Path $folder $productLink)) { throw "Uninstall left $productLink in $folder." }
            }
            Assert-DataKept
        })
    }
    if ($script:adapter -and -not $script:adapter.HasExited) { $script:adapter.Kill() }
    [void] (Test-Stage $Phase 'reset' { Reset-Machine })
}

function Test-MsiUpgrade([string] $Phase) {
    $directory = Join-Path $scratch "$Phase directory"
    $oldProgram = Join-Path $directory $old.Binary
    $program = Join-Path $directory $new.Binary
    $oldCode = Msi-Property $baselineMsi 'ProductCode'
    $newCode = Msi-Property $candidateMsi 'ProductCode'
    $ready = Test-Stage $Phase 'install 1.14.4 with data, credentials, a login entry and the oldest shortcut names' {
        Run-Installer 'msiexec.exe' ('/i "{0}" /qn /norestart INSTALLDIR="{1}" /l*v "{2}"' -f $baselineMsi, $directory, (Join-Path $scratch 'old-msi.log'))
        Write-Output "MSI registered directory before the upgrade: $((Get-ItemProperty -LiteralPath $oldProductKey).InstallDir)"
        # The per-machine MSI puts its shortcuts in the all-users folders; the per-user ones are checked too.
        $script:msiDesktopLink = Find-Shortcut @((Join-Path $commonDesktop $productLink), (Join-Path $desktop $productLink))
        $script:msiStartLink = Find-Shortcut @((Join-Path $commonPrograms "$($new.Product)\$productLink"), (Join-Path $programs "$($new.Product)\$productLink"))
        Assert-Shortcut $script:msiDesktopLink $oldProgram ''
        Assert-Shortcut $script:msiStartLink $oldProgram ''
        New-LegacyState $directory
        # What the oldest MSIs left: a desktop shortcut and a Start menu folder with shortcuts under the earlier name.
        $legacyFolder = Join-Path (Split-Path (Split-Path $script:msiStartLink)) $old.Installer
        New-Item -ItemType Directory -Force $legacyFolder | Out-Null
        $script:msiLegacyLinks = @((Join-Path (Split-Path $script:msiDesktopLink) $legacyLink), (Join-Path $legacyFolder $legacyLink), (Join-Path $legacyFolder "Uninstall $legacyLink"))
        foreach ($link in $script:msiLegacyLinks) { Copy-Item -LiteralPath $script:msiStartLink -Destination $link -Force }
    }
    if ($ready) {
        # As in the NSIS phases: the read works on the known 1.14.4 value (the MSI's desktop shortcut has none).
        [void] (Test-Stage $Phase '1.14.4 Start menu shortcut carries its AppUserModelID' { Assert-ShortcutModel $script:msiStartLink $old.AppId })
    }
    $upgraded = $ready -and (Test-Stage $Phase 'major upgrade' {
        Run-Installer 'msiexec.exe' ('/i "{0}" /qn /norestart /l*v "{1}"' -f $candidateMsi, (Join-Path $scratch 'new-msi.log'))
        if ((Msi-ProductState $oldCode) -ne -1) { throw 'The previous MSI is still registered.' }
        if ((Msi-ProductState $newCode) -ne 5) { throw 'The candidate MSI is not installed.' }
    })
    if ($upgraded) {
        [void] (Test-Stage $Phase 'one registration in the same directory' {
            Assert-OneRegistration
            $installDir = (Get-ItemProperty -LiteralPath $newProductKey).InstallDir
            Write-Output "MSI registered directory after the upgrade: $installDir"
            if ($installDir.TrimEnd('\') -ne $directory) { throw 'MSI moved the existing installation.' }
            if ((Test-Path -LiteralPath $oldProductKey) -and $null -ne (Get-Item -LiteralPath $oldProductKey).GetValue('InstallDir')) { throw 'The earlier MSI directory value is still registered.' }
        })
        [void] (Test-Stage $Phase 'only the current executables' { Assert-Executables $directory })
        [void] (Test-Stage $Phase 'shortcuts start the current executable; the oldest names are gone' {
            Assert-Shortcut $script:msiDesktopLink $program ''
            Assert-Shortcut $script:msiStartLink $program $new.AppId
            foreach ($link in $script:msiLegacyLinks) { if (Test-Path -LiteralPath $link) { throw "The upgrade left $link." } }
            $legacyFolder = Split-Path $script:msiLegacyLinks[1]
            if (Test-Path -LiteralPath $legacyFolder) { throw "The upgrade left $legacyFolder." }
        })
        [void] (Test-Stage $Phase 'data, credentials and login entry left for the app' { Assert-DataUntouched })
        [void] (Test-Stage $Phase 'first start moves data, credentials and the login entry' {
            Invoke-FirstStart $directory
            Assert-Moved $directory
        })
        [void] (Test-Stage $Phase 'console helper prints the usage' { Assert-ConsoleHelper $directory })
        [void] (Test-Stage $Phase 'uninstall removes the installation and keeps the data' {
            Stop-App $program
            Run-Installer 'msiexec.exe' ('/x "{0}" /qn /norestart' -f $newCode)
            if ((Msi-ProductState $newCode) -ne -1) { throw 'The candidate MSI did not uninstall.' }
            if (@(Get-InstallEntries).Count -ne 0) { throw 'The uninstall left an install entry.' }
            if (Test-Path -LiteralPath $directory) { throw "Uninstall left $directory with $((Get-ChildItem -LiteralPath $directory -Force).Name -join ', ')." }
            foreach ($link in @($script:msiDesktopLink, $script:msiStartLink)) { if (Test-Path -LiteralPath $link) { throw "Uninstall left $link." } }
            Assert-DataKept
        })
    }
    [void] (Test-Stage $Phase 'reset' { Reset-Machine })
}

# Candidate and baseline packages.
$newNsis = @(Get-ChildItem 'src-tauri/target/release/bundle/nsis' -Filter '*-setup.exe')
$newMsi = @(Get-ChildItem 'src-tauri/target/release/bundle/msi' -Filter '*.msi')
if ($newNsis.Count -ne 1 -or $newMsi.Count -ne 1) { throw 'Expected one candidate installer per format.' }
$candidateNsis = $newNsis[0].FullName
$candidateMsi = $newMsi[0].FullName
[void] (Test-Stage 'packages' 'the MSI keeps its UpgradeCode under the current name and publisher' {
    $oldUpgrade = [guid] (Msi-Property $baselineMsi 'UpgradeCode')
    $newUpgrade = [guid] (Msi-Property $candidateMsi 'UpgradeCode')
    if ($oldUpgrade -ne $newUpgrade -or $newUpgrade -ne [guid] $new.UpgradeCode) { throw "MSI UpgradeCode changed: $oldUpgrade / $newUpgrade" }
    if ((Msi-Property $baselineMsi 'Manufacturer') -ne $old.Manufacturer) { throw 'The baseline MSI does not have the manufacturer scripts/legacy-identity.json records.' }
    if ((Msi-Property $candidateMsi 'ProductName') -ne $new.Product) { throw "The candidate MSI is not $($new.Product)." }
    if ((Msi-Property $candidateMsi 'Manufacturer') -ne $new.Publisher) { throw "The candidate MSI is not published by $($new.Publisher)." }
    Write-Output "Verified the published MSI UpgradeCode is preserved: $newUpgrade"
})
[void] (Test-Stage 'start' 'a clean machine' { Reset-Machine })
# The in-app update first (Review Focus 4), then the installer run by hand, then the MSI.
Test-NsisUpgrade 'nsis update' '/P /R /UPDATE /ARGS' -Updater
Test-NsisUpgrade 'nsis by hand' '/S'
Test-MsiUpgrade 'msi'

if ($failures.Count -ne 0) {
    Write-Host "$($failures.Count) upgrade check(s) failed:"
    foreach ($failure in $failures) { Write-Host "  $failure" }
    throw "$($failures.Count) upgrade check(s) failed; see the list above."
}
Write-Output "NSIS (through the updater and by hand) and the MSI upgraded $baselineTag in place to one $($new.Product) installation by $($new.Publisher); its first start moved data, both credentials and the login entry."
# The expected CLI usage checks exit with 2. GitHub's pwsh wrapper forwards
# LASTEXITCODE unless the successful validation script returns an explicit 0.
exit 0
