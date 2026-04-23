param(
    [string]$Uri = ''
)

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendPath = Join-Path $repoRoot 'backend'
$pythonPath = Join-Path $backendPath '.venv\Scripts\python.exe'
$healthUrl = 'http://127.0.0.1:8765/health'

try {
    Invoke-WebRequest $healthUrl -UseBasicParsing -TimeoutSec 2 | Out-Null
    exit 0
} catch {
}

if (-not (Test-Path $pythonPath)) {
    Write-Host 'backend\.venv topilmadi. Avval setup_project.bat ni ishlating.'
    exit 1
}

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location `"$backendPath`"; .\.venv\Scripts\python.exe local_agent.py"
