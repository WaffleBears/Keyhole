param([switch]$Debug, [switch]$InstallPrereqs, [switch]$RefetchSkia)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Test-Command([string]$name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

function Find-Vs {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $null }
    & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
}

$missing = @()
$installs = @()
if (-not (Test-Command cargo)) { $missing += "Rust toolchain (cargo)"; $installs += "Rustlang.Rustup" }
if (-not (Find-Vs)) {
    $missing += "Visual Studio 2022 C++ build tools (MSVC x64)"
    $installs += 'Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --wait"'
}
if (-not (Test-Command clang-cl)) { $missing += "LLVM clang-cl"; $installs += "LLVM.LLVM" }
if (-not (Test-Command ninja)) { $missing += "ninja"; $installs += "Ninja-build.Ninja" }
if (-not (Test-Command git)) { $missing += "git"; $installs += "Git.Git" }
$py = $false
if (Test-Command python) { $py = ((& python --version 2>&1) -join "") -like "Python 3.*" }
if (-not $py) { $missing += "Python 3"; $installs += "Python.Python.3.12" }

if ($missing.Count -gt 0) {
    Write-Host "Missing build prerequisites:"
    $missing | ForEach-Object { Write-Host "  $_" }
    if ($InstallPrereqs) {
        if (-not (Test-Command winget)) { throw "winget is not available; install the prerequisites by hand" }
        foreach ($id in $installs) {
            Write-Host "winget install $id"
            Invoke-Expression "winget install --accept-source-agreements --accept-package-agreements -e --id $id"
        }
        Write-Host "Prerequisites installed. Open a new terminal so PATH picks them up, then run build.ps1 again."
        exit 0
    }
    Write-Host "Install them (winget ids: $($installs -join ', ')) or rerun with -InstallPrereqs."
    exit 1
}

$fetchArgs = @{}
if ($RefetchSkia) { $fetchArgs.Force = $true }
& (Join-Path $root "tools\fetch-skia.ps1") @fetchArgs
if ($LASTEXITCODE -ne 0) { throw "fetching Skia failed" }

$profile = if ($Debug) { "debug" } else { "release" }
$cargoArgs = @("build")
if (-not $Debug) { $cargoArgs += "--release" }
Write-Host "== cargo $($cargoArgs -join ' ')"
if (-not (Test-Path (Join-Path $root "target\$profile\build"))) {
    Write-Host "First build compiles Skia from source; expect 10 to 30 minutes."
}
Push-Location $root
try { & cargo @cargoArgs } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$exe = Join-Path $root "target\$profile\keyhole.exe"
if (-not (Test-Path $exe)) { throw "$exe was not produced" }
$bytes = [System.IO.File]::ReadAllBytes($exe)
function Get-ImportedDlls([byte[]]$b) {
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    $sections = [BitConverter]::ToUInt16($b, $pe + 6)
    $optSize = [BitConverter]::ToUInt16($b, $pe + 20)
    $opt = $pe + 24
    $magic = [BitConverter]::ToUInt16($b, $opt)
    $dir = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
    $importRva = [BitConverter]::ToUInt32($b, $dir + 8)
    if ($importRva -eq 0) { return @() }
    $secTable = $opt + $optSize
    $map = @()
    for ($i = 0; $i -lt $sections; $i++) {
        $s = $secTable + $i * 40
        $map += ,@([BitConverter]::ToUInt32($b, $s + 12), [BitConverter]::ToUInt32($b, $s + 16), [BitConverter]::ToUInt32($b, $s + 20))
    }
    $toOffset = { param($rva) foreach ($m in $map) { if ($rva -ge $m[0] -and $rva -lt $m[0] + $m[1]) { return $rva - $m[0] + $m[2] } } return -1 }
    $names = @()
    $desc = & $toOffset $importRva
    while ($desc -ge 0) {
        $nameRva = [BitConverter]::ToUInt32($b, $desc + 12)
        if ($nameRva -eq 0) { break }
        $off = & $toOffset $nameRva
        if ($off -lt 0) { break }
        $end = $off
        while ($b[$end] -ne 0) { $end++ }
        $names += [System.Text.Encoding]::ASCII.GetString($b, $off, $end - $off)
        $desc += 20
    }
    return $names
}
$imports = Get-ImportedDlls $bytes
$dynamic = $imports | Where-Object { $_ -match '^(vcruntime|msvcp|api-ms-win-crt-|ucrtbase)' }
if ($dynamic.Count -gt 0) {
    throw "keyhole.exe imports the dynamic C runtime ($($dynamic -join ', ')); check .cargo\config.toml has +crt-static and that Skia was compiled from source"
}
$unexpected = $imports | Where-Object { $_ -notmatch '^(kernel32|user32|gdi32|advapi32|shell32|ole32|oleaut32|ws2_32|iphlpapi|ntdll|crypt32|wintrust|netapi32|dnsapi|httpapi|iscsidsc|wevtapi|wtsapi32|secur32|bcrypt|d3d12|dxgi|dxguid|d3dcompiler|opengl32|imm32|uxtheme|dwmapi|shlwapi|comdlg32|comctl32|version|psapi|setupapi|winmm|usp10|msimg32|fwpuclnt|dbghelp|dwrite|bcryptprimitives|tdh|combase|powrprof|userenv|wldap32|winspool|cabinet|activeds|netutils|srvcli|wkscli|samcli|logoncli|mpr|dhcpcsvc|windows\.|api-ms-win-core|ext-ms-)' }
if ($unexpected.Count -gt 0) { Write-Host "note: keyhole.exe also imports $($unexpected -join ', ')" }
$mb = [math]::Round($bytes.Length / 1MB, 1)
Write-Host "Built $exe ($mb MB)"
