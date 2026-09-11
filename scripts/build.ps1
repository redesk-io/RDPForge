param(
  [string]$Config = "Release",
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Missing '$cmd'. $hint"
  }
}

Need zig "Install Zig 0.15.2 from https://ziglang.org/download/ and add it to PATH."
Need dotnet "Install .NET 8 SDK from https://dotnet.microsoft.com/download (builds the net472 GUI too)."

git submodule update --init --recursive

if (-not $SkipTests) {
  zig build test --summary all
  if ($LASTEXITCODE -ne 0) { throw "HookTest failed" }
  zig build test-installer --summary all
  if ($LASTEXITCODE -ne 0) { throw "InstallerTest failed" }
}

zig build -Doptimize=$Config --summary all
if ($LASTEXITCODE -ne 0) { throw "zig build failed" }

dotnet build src/ManagerGui/ManagerGui.csproj -c $Config
if ($LASTEXITCODE -ne 0) { throw "ManagerGui build failed" }

Write-Host ""
Write-Host "Outputs:"
Write-Host "  zig-out\bin\<arch>-windows-gnu\ForgeHook.dll"
Write-Host "  zig-out\bin\<arch>-windows-gnu\InstallerCli.exe"
Write-Host "  src\ManagerGui\bin\$Config\net472\ManagerGui.exe"
