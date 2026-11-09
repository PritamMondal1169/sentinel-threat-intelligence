$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$commits = @(
    @{ hash = "75364f3"; label = "Commit 1/11: Project foundation, configurations, and dependencies" },
    @{ hash = "63ebbba"; label = "Commit 2/11: Core security utilities, SSRF protection, and normalizer" },
    @{ hash = "62378c0"; label = "Commit 3/11: Threat intelligence feeds, CT logs, TLS, and DNS/RDAP" },
    @{ hash = "1671189"; label = "Commit 4/11: Module 3 AI Scam DNA, Gemini LLM, and MinHash clustering" },
    @{ hash = "868d3ca"; label = "Commit 5/11: Correlation engine, 3-sigma scam radar, and risk assessor" },
    @{ hash = "dbf28df"; label = "Commit 6/11: RFC 8785 blockchain anchoring, LocalLedger, and ReportRegistry.sol" },
    @{ hash = "04db7e1"; label = "Commit 7/11: SQLite storage engine, orchestrator pipeline, and seed demo" },
    @{ hash = "7698fbe"; label = "Commit 8/11: REST API layer, JWT authentication, RBAC, and background jobs" },
    @{ hash = "7551d0b"; label = "Commit 9/11: 14-screen unified SOC dashboard with canvas threat visualizer" },
    @{ hash = "16e337a"; label = "Commit 10/11: Production Dockerfile, Nginx reverse proxy, and deploy automation" },
    @{ hash = "a8d8f48"; label = "Commit 11/11: Complete test suite and PRD Section 25 correlation benchmark" }
)

Write-Host "=========================================================="
Write-Host "    Pushing SENTINEL Commits to GitHub One by One         "
Write-Host "=========================================================="

foreach ($c in $commits) {
    $h = $c.hash
    $l = $c.label
    Write-Host ""
    Write-Host ">>> Pushing $l [$h]..."
    git push origin "${h}:refs/heads/main"
    Write-Host "Successfully pushed $h"
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "=========================================================="
Write-Host " All 11 commits successfully pushed to GitHub!           "
Write-Host " View: https://github.com/PritamMondal1169/sentinel-threat-intelligence"
Write-Host "=========================================================="
