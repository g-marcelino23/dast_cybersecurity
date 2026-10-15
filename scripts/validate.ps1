$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
$pytestTemp = Join-Path $root ".pytest-tmp"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Ambiente .venv ausente. Crie-o com Python 3.11, 3.12 ou 3.13."
}

& $python --version
& $python -m pytest (Join-Path $root "backend\tests") -q `
    "--basetemp=$pytestTemp" -p no:cacheprovider
& $python -m ruff check (Join-Path $root "backend\app") (Join-Path $root "backend\tests")
& $python -m mypy (Join-Path $root "backend\app")
& npm.cmd test --prefix (Join-Path $root "frontend")
& npm.cmd run typecheck --prefix (Join-Path $root "frontend")
& npm.cmd run lint --prefix (Join-Path $root "frontend")
& npm.cmd run build --prefix (Join-Path $root "frontend")
& npm.cmd audit --prefix (Join-Path $root "frontend") --omit=dev

Write-Host "Validacao concluida sem erros." -ForegroundColor Green
