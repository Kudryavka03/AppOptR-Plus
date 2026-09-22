[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\out")
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$mainManifest = Join-Path $repoRoot "AppOptR\Cargo.toml"
$ebpfManifest = Join-Path $repoRoot "appopt-ebpf\Cargo.toml"
$packageFiles = Join-Path $repoRoot "packaging"
$mainBinary = Join-Path $repoRoot "AppOptR\target\aarch64-linux-android\release\AppOpt"
$ebpfBinary = Join-Path $repoRoot "appopt-ebpf\target\bpfel-unknown-none\release\AppOpt-ebpf"

if (-not (Test-Path -LiteralPath $packageFiles)) {
    throw "Missing packaging directory: $packageFiles"
}

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path -LiteralPath $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

$ndkRoot = $env:ANDROID_NDK_HOME
if (-not $ndkRoot) {
    $ndkRoot = $env:ANDROID_NDK_ROOT
}
if (-not $ndkRoot) {
    $ndkParent = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
    if (Test-Path -LiteralPath $ndkParent) {
        $ndkRoot = Get-ChildItem -LiteralPath $ndkParent -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $ndkRoot) {
    throw "Android NDK was not found. Set ANDROID_NDK_HOME before packaging."
}

$ndkBin = Join-Path $ndkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin"
$androidLinker = Join-Path $ndkBin "aarch64-linux-android21-clang.cmd"
if (-not (Test-Path -LiteralPath $androidLinker)) {
    throw "Android arm64 linker was not found: $androidLinker"
}

$bpfLinker = (Get-Command bpf-linker -ErrorAction SilentlyContinue).Source
if (-not $bpfLinker) {
    throw "bpf-linker is required. Install a compatible bpf-linker and add it to PATH."
}

if (-not $SkipBuild) {
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $androidLinker
    & cargo build --locked --release --target aarch64-linux-android --manifest-path $mainManifest
    if ($LASTEXITCODE -ne 0) {
        throw "Android user-space build failed."
    }

    $env:CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER = $bpfLinker
    & cargo +nightly build --locked --release -Z build-std=core --target bpfel-unknown-none --manifest-path $ebpfManifest
    if ($LASTEXITCODE -ne 0) {
        throw "eBPF build failed."
    }
}

foreach ($artifact in @($mainBinary, $ebpfBinary)) {
    if (-not (Test-Path -LiteralPath $artifact)) {
        throw "Missing build artifact: $artifact"
    }
}

$versionMatch = Select-String -LiteralPath $mainManifest -Pattern '^version\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $versionMatch) {
    throw "Could not read package version from $mainManifest"
}
$version = $versionMatch.Matches[0].Groups[1].Value
$versionParts = $version.Split('.')
if ($versionParts.Count -lt 3) {
    throw "Version must be semantic major.minor.patch: $version"
}
if (@($versionParts[0..2] | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
    throw "Version must be semantic major.minor.patch: $version"
}
$versionCode = ([int]$versionParts[0] * 10000) + ([int]$versionParts[1] * 100) + [int]$versionParts[2]

$stage = Join-Path $env:TEMP ("appoptr-plus-package-" + [guid]::NewGuid().ToString("N"))
$outputPath = Join-Path $OutputDirectory ("AppOptR-Plus-v" + $version + "-arm64.zip")
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

try {
    Copy-Item -LiteralPath (Join-Path $packageFiles "module.prop") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "skip_mount") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "customize.sh") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "service.sh") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "uninstall.sh") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "action.sh") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $packageFiles "webroot") -Destination (Join-Path $stage "webroot") -Recurse
    $binDirectory = Join-Path $stage "bin"
    New-Item -ItemType Directory -Path $binDirectory | Out-Null
    Copy-Item -LiteralPath $mainBinary -Destination (Join-Path $binDirectory "AppOpt")
    Copy-Item -LiteralPath $ebpfBinary -Destination (Join-Path $binDirectory "AppOpt-ebpf")

    $propPath = Join-Path $stage "module.prop"
    $prop = Get-Content -LiteralPath $propPath -Raw
    $prop = [regex]::Replace($prop, '(?m)^version=.*$', "version=$version")
    $prop = [regex]::Replace($prop, '(?m)^versionCode=.*$', "versionCode=$versionCode")
    [System.IO.File]::WriteAllText($propPath, $prop, [System.Text.UTF8Encoding]::new($false))

    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $outputPath -Force
    Write-Output "KernelSU package created: $outputPath"
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
