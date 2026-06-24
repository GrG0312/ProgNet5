# Run from the project root folder (where lab.conf lives)
$root = $PSScriptRoot

Write-Host "Compiling client.p4..." -ForegroundColor Yellow
docker run --rm -v "${root}:/workspace" p4lang/p4c `
    p4c --target bmv2 --arch v1model -o /workspace/shared /workspace/p4/client.p4
if ($LASTEXITCODE -ne 0) { Write-Host "FAILED" -ForegroundColor Red; exit 1 }
Write-Host "OK" -ForegroundColor Green

Write-Host "Compiling server.p4..." -ForegroundColor Yellow
docker run --rm -v "${root}:/workspace" p4lang/p4c `
    p4c --target bmv2 --arch v1model -o /workspace/shared /workspace/p4/server.p4
if ($LASTEXITCODE -ne 0) { Write-Host "FAILED" -ForegroundColor Red; exit 1 }
Write-Host "OK" -ForegroundColor Green

Write-Host "Output: shared/client.json, shared/server.json" -ForegroundColor Cyan
