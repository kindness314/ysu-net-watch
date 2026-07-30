param(
    [string]$OutputName = "ysu-net-watch"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$launcher = Join-Path $projectRoot "packaging\launcher.py"
$release = Join-Path $projectRoot "release"
$work = Join-Path $projectRoot ".tmp\pyinstaller"
$spec = Join-Path $projectRoot ".tmp"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Virtual environment not found: $python"
}

& $python -m PyInstaller `
    --noconfirm `
    --onefile `
    --console `
    --name $OutputName `
    --paths (Join-Path $projectRoot "src") `
    --distpath $release `
    --workpath $work `
    --specpath $spec `
    $launcher

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$exe = Join-Path $release "$OutputName.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Expected executable was not created: $exe"
}

Get-FileHash -Algorithm SHA256 -LiteralPath $exe
