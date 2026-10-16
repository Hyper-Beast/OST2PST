# Build and test with the VS 2022 installation discovered by scripts/dev.cmd.
param(
    [ValidateSet('Debug', 'Release')] [string] $Config = 'Release',
    [string] $BuildDir = 'build',
    [switch] $ConfigureOnly,
    [switch] $SkipTests
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
function Invoke-DevCmd {
    param([string] $Command)
    & cmd.exe /c "scripts\dev.cmd $Command"
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Command" }
}
Push-Location $repo
try {
    Invoke-DevCmd "cmake -S . -B `"$BuildDir`" -G `"Visual Studio 17 2022`" -A x64"
    if (-not $ConfigureOnly) {
        Invoke-DevCmd "cmake --build `"$BuildDir`" --config $Config --parallel 4"
        if (-not $SkipTests) {
            Invoke-DevCmd "ctest --test-dir `"$BuildDir`" -C $Config --output-on-failure"
        }
    }
} finally { Pop-Location }
