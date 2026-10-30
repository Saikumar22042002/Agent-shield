# AgentShield — Windows equivalent of `make dev` / `make test` / `make e2e`. Usage: .\dev.ps1 [dev|setup|test|e2e]
param([string]$Task = "dev")
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Venv = Join-Path $Root "backend\.venv"
$Py = Join-Path $Venv "Scripts\python.exe"

function Setup {
    if (-not (Test-Path $Py)) {
        Write-Host ">> Creating Python 3.11 venv"
        py -3.11 -m venv $Venv
        & $Py -m pip install --upgrade pip
    }
    $marker = Join-Path $Venv ".installed"
    $req = Join-Path $Root "backend\requirements.txt"
    if (-not (Test-Path $marker) -or (Get-Item $req).LastWriteTime -gt (Get-Item $marker).LastWriteTime) {
        & $Py -m pip install -r $req
        New-Item -ItemType File -Force $marker | Out-Null
    }
    if (-not (Test-Path (Join-Path $Root "frontend\node_modules"))) {
        Push-Location (Join-Path $Root "frontend"); npm install --no-audit --no-fund; Pop-Location
    }
    $envFile = Join-Path $Root ".env"
    if (-not (Test-Path $envFile)) {
        Copy-Item (Join-Path $Root ".env.example") $envFile
        Write-Host ">> Created .env from .env.example - fill in TARGET_HARNESS_ARN / TARGET_REGION / AWS_PROFILE."
    }
}

switch ($Task) {
    "setup" { Setup }
    "test" {
        Setup
        Push-Location (Join-Path $Root "backend"); & $Py -m pytest -q; $backend = $LASTEXITCODE; Pop-Location
        Push-Location (Join-Path $Root "frontend"); npx tsc -b; if ($LASTEXITCODE -eq 0) { npm test }; $frontend = $LASTEXITCODE; Pop-Location
        if ($backend -ne 0 -or $frontend -ne 0) { exit 1 }
    }
    "e2e" { Setup; Push-Location (Join-Path $Root "backend"); & $Py scripts\e2e_smoke.py; $code = $LASTEXITCODE; Pop-Location; exit $code }
    "dev" {
        Setup
        # Own console window: on Windows, uvicorn --reload stops its worker with CTRL_C_EVENT, which would
        # otherwise also hit Vite and this script because they share the console.
        $api = Start-Process -FilePath $Py -PassThru -WindowStyle Minimized -ArgumentList @(
            "-m", "uvicorn", "agentshield.app:app", "--app-dir", "backend", "--host", "127.0.0.1", "--port", "8000",
            "--reload", "--reload-dir", "backend/agentshield", "--timeout-graceful-shutdown", "3") -WorkingDirectory $Root
        try {
            Push-Location (Join-Path $Root "frontend")
            $env:AGENTSHIELD_API = "http://127.0.0.1:8000"
            npm run dev
        } finally {
            Pop-Location
            if (-not $api.HasExited) { taskkill /PID $api.Id /T /F | Out-Null }
        }
    }
    default { Write-Error "Unknown task '$Task' (use dev, setup, test or e2e)" }
}
