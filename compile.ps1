# compile.ps1

# Create build directory if it doesn't exist
New-Item -ItemType Directory -Force -Path build | Out-Null

Write-Host "Compiling client.p4..." -ForegroundColor Yellow

docker run --rm -v ${PWD}:/workspace p4lang/p4c `
    p4c --target bmv2 `
    --arch v1model `
    --p4runtime-files /workspace/build/client.p4info.txt `
    --p4runtime-format text `
    -o /workspace/build/client.json `
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
    --p4runtime-files /workspace/build/server.p4info.txt `
    --p4runtime-format text `
    -o /workspace/build/server.json `
    /workspace/p4/server.p4

if ($LASTEXITCODE -eq 0) {
    Write-Host "Server compilation successful!" -ForegroundColor Green
} else {
    Write-Host "Server compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Output files:" -ForegroundColor Green
Write-Host "  build/client.json" -ForegroundColor Green
Write-Host "  build/client.p4info.txt" -ForegroundColor Green
Write-Host "  build/server.json" -ForegroundColor Green
Write-Host "  build/server.p4info.txt" -ForegroundColor Green