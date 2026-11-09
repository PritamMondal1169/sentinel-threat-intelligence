# ==============================================================================
# SENTINEL Production Deployment Script (Windows PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "      SENTINEL Intelligence Network Production Setup      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Docker
try {
    $dockerVersion = docker --version
    Write-Host "[+] Docker detected: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Error "Docker is not installed or not running in this environment. Please start Docker Desktop."
    exit 1
}

# 2. Setup .env file
if (-not (Test-Path ".env")) {
    Write-Host "[+] Initializing .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    
    $jwtBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($jwtBytes)
    $jwtSecret = [System.Convert]::ToBase64String($jwtBytes)

    (Get-Content ".env") -replace "SENTINEL_JWT_SECRET=.*", "SENTINEL_JWT_SECRET=$jwtSecret" | Set-Content ".env"
    Write-Host "[+] Generated cryptographically secure SENTINEL_JWT_SECRET." -ForegroundColor Green
}

# 3. Build & Run
Write-Host "[+] Building and starting containers..." -ForegroundColor Yellow
docker compose up -d --build

# 4. Wait for health
Write-Host "[+] Waiting for health probe..." -ForegroundColor Yellow
$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($resp.status -eq "ok") {
            $healthy = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 2
}

if ($healthy) {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "             SENTINEL IS LIVE & DEPLOYED                  " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Web Dashboard:      http://localhost"
    Write-Host "API Documentation:  http://localhost/docs"
    Write-Host "Health Probe:       http://localhost/health"
    Write-Host "Default Admin:      username=admin"
} else {
    Write-Host "[!] Note: Check logs via 'docker compose logs -f' if proxy took longer to start." -ForegroundColor Yellow
}

