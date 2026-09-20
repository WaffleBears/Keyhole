param([switch]$Force)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "skia"

function Locked-Version {
    $lock = Join-Path $root "Cargo.lock"
    if (-not (Test-Path $lock)) { return $null }
    $m = [regex]::Match((Get-Content $lock -Raw), 'name = "skia-bindings"\r?\nversion = "([^"]+)"')
    if ($m.Success) { $m.Groups[1].Value } else { $null }
}

function Find-Crate {
    $wanted = Locked-Version
    $dirs = Get-ChildItem "$env:USERPROFILE\.cargo\registry\src\index.crates.io-*\skia-bindings-*" -Directory -ErrorAction SilentlyContinue
    if ($wanted) { $dirs = $dirs | Where-Object { $_.Name -eq "skia-bindings-$wanted" } }
    $dirs | Sort-Object Name -Descending | Select-Object -First 1
}

$crate = Find-Crate
if (-not $crate) {
    Write-Host "Fetching crates so the skia-bindings version is known"
    Push-Location $root
    try { cargo fetch } finally { Pop-Location }
    $crate = Find-Crate
}
if (-not $crate) { throw "skia-bindings is not in the cargo registry. Did cargo fetch fail?" }
$tag = (Select-String -Path (Join-Path $crate.FullName "Cargo.toml") -Pattern '^skia = "(.+)"').Matches[0].Groups[1].Value
$stamp = Join-Path $dest ".keyhole-skia-tag"

if (-not $Force -and (Test-Path $stamp) -and ((Get-Content $stamp -Raw).Trim() -eq $tag) -and (Test-Path (Join-Path $dest "bin\gn.exe"))) {
    Write-Host "Skia $tag is already present in $dest"
    exit 0
}

Write-Host "$($crate.Name) wants Skia $tag"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
$tar = Join-Path $env:TEMP "skia-$tag.tar.gz"
if ($Force -and (Test-Path $tar)) { Remove-Item -Force $tar }
if (-not (Test-Path $tar)) {
    Write-Host "Downloading Skia $tag"
    $partial = "$tar.partial"
    if (Test-Path $partial) { Remove-Item -Force $partial }
    Invoke-WebRequest -Uri "https://codeload.github.com/rust-skia/skia/tar.gz/$tag" -OutFile $partial
    Move-Item -Force $partial $tar
}

$py = @'
import tarfile, os, shutil, sys, posixpath
src, dest = sys.argv[1], sys.argv[2]
os.makedirs(dest)
tf = tarfile.open(src, "r:gz")
links = []
for m in tf:
    parts = m.name.split("/", 1)
    if len(parts) < 2:
        continue
    rel = parts[1]
    if rel == "infra" or rel.startswith("infra/"):
        continue
    out = os.path.join(dest, rel.replace("/", os.sep))
    if m.isdir():
        os.makedirs(out, exist_ok=True)
    elif m.issym():
        links.append((rel, m.linkname))
    elif m.isfile():
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with tf.extractfile(m) as f, open(out, "wb") as g:
            shutil.copyfileobj(f, g)
for rel, target in links:
    s = os.path.join(dest, posixpath.normpath(posixpath.join(posixpath.dirname(rel), target)).replace("/", os.sep))
    d = os.path.join(dest, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(d), exist_ok=True)
    if os.path.isdir(s):
        shutil.copytree(s, d, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d)
'@
$script = Join-Path $env:TEMP "unpack-skia.py"
Set-Content -Path $script -Value $py -Encoding UTF8
Write-Host "Unpacking into $dest"
python $script $tar $dest
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Force $tar -ErrorAction SilentlyContinue
    throw "unpacking Skia failed. The downloaded archive was discarded, run again to fetch it afresh"
}

Write-Host "Syncing Skia third-party dependencies"
$env:GIT_CONFIG_COUNT = "1"
$env:GIT_CONFIG_KEY_0 = "core.longpaths"
$env:GIT_CONFIG_VALUE_0 = "true"
$env:GIT_SYNC_DEPS_PATH = "DEPS"
$env:GIT_SYNC_DEPS_SKIP_EMSDK = "1"
Push-Location $dest
try { python tools/git-sync-deps } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "git-sync-deps failed" }
if (-not (Test-Path (Join-Path $dest "bin\gn.exe"))) { throw "gn.exe was not fetched" }
Set-Content -Path $stamp -Value $tag
Write-Host "Skia $tag is ready in $dest"
