# compile.ps1

Write-Host "Compiling client.p4..." -ForegroundColor Yellow

docker run --rm -v ${PWD}:/workspace p4lang/p4c `
    p4c --target bmv2 `
    --arch v1model `
    -o /workspace/shared/client.json `
    /workspace/p4/client.p4

if ($LASTEXITCODE -eq 0) {
    Write-Host "Client compilation successful!" -ForegroundColor Green
} else {
    Write-Host "Client compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Compiling server.p4..." -ForegroundColor Yellow

docker run --rm -v ${PWD}:/workspace p4lang/p4c `
    p4c --target bmv2 `
    --arch v1model `
    -o /workspace/shared/server.json `
    /workspace/p4/server.p4

if ($LASTEXITCODE -eq 0) {
    Write-Host "Server compilation successful!" -ForegroundColor Green
} else {
    Write-Host "Server compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Output files:" -ForegroundColor Green
Write-Host "  shared/client.json" -ForegroundColor Green
Write-Host "  shared/server.json" -ForegroundColor Green
