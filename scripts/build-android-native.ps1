param(
    [Parameter(Mandatory = $true)][string]$NdkPath,
    [string]$AndroidProject,
    [string]$Version = '0.5.8',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../output/android')
)
$ErrorActionPreference = 'Stop'
$taskSourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$taskNdkRoot = (Resolve-Path -LiteralPath $NdkPath).Path
$taskToolchain = Join-Path $taskNdkRoot 'toolchains/llvm/prebuilt/windows-x86_64/bin'
if (!(Test-Path -LiteralPath $taskToolchain)) { throw 'This script requires the Windows NDK toolchain.' }
$taskGo = (Get-Command go -ErrorAction Stop).Source
$taskTargets = @(
    @{ abi='armeabi-v7a'; arch='arm'; compiler='armv7a-linux-androideabi26-clang.cmd' },
    @{ abi='arm64-v8a'; arch='arm64'; compiler='aarch64-linux-android26-clang.cmd' },
    @{ abi='x86'; arch='386'; compiler='i686-linux-android26-clang.cmd' },
    @{ abi='x86_64'; arch='amd64'; compiler='x86_64-linux-android26-clang.cmd' }
)
$taskSavedEnv = @{}
foreach ($name in @('GOOS','GOARCH','GOARM','CGO_ENABLED','CC')) { $taskSavedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $taskSourceRoot
try {
    foreach ($target in $taskTargets) {
        $env:GOOS='android'; $env:GOARCH=$target.arch; $env:CGO_ENABLED='1'
        $env:GOARM=if ($target.arch -eq 'arm') { '7' } else { '' }
        $env:CC=Join-Path $taskToolchain $target.compiler
        $taskAbiOutput=New-Item -ItemType Directory -Force -Path (Join-Path $OutputDirectory $target.abi)
        $taskBinary=Join-Path $taskAbiOutput.FullName 'libopenflux.so'
        & $taskGo build -trimpath -buildmode=pie -ldflags "-s -w -X main.buildVersion=$Version" -o $taskBinary .
        if ($LASTEXITCODE -ne 0) { throw "Native build failed for $($target.abi)" }
        if ($AndroidProject) {
            $taskBundlePath=New-Item -ItemType Directory -Force -Path (Join-Path $AndroidProject "app/src/main/jniLibs/$($target.abi)")
            Copy-Item -LiteralPath $taskBinary -Destination (Join-Path $taskBundlePath.FullName 'libopenflux.so')
        }
        Write-Output "Built $($target.abi)"
    }
} finally {
    Pop-Location
    foreach ($name in $taskSavedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $taskSavedEnv[$name], 'Process') }
}
