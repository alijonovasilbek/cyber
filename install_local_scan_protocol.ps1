$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcherPath = Join-Path $repoRoot 'launch_local_agent.ps1'

if (-not (Test-Path $launcherPath)) {
    Write-Host 'launch_local_agent.ps1 topilmadi.'
    exit 1
}

$baseKey = 'HKCU:\Software\Classes\cyberguard-agent'
$commandKey = Join-Path $baseKey 'shell\open\command'
$commandValue = "powershell.exe -ExecutionPolicy Bypass -File `"$launcherPath`" `"%1`""

New-Item -Path $baseKey -Force | Out-Null
Set-ItemProperty -Path $baseKey -Name '(default)' -Value 'URL:CyberGuard Local Agent' -Force
New-ItemProperty -Path $baseKey -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
New-Item -Path $commandKey -Force | Out-Null
Set-ItemProperty -Path $commandKey -Name '(default)' -Value $commandValue -Force

Write-Host 'cyberguard-agent:// protocol o''rnatildi.'
Write-Host 'Endi saytdagi RUN LOCAL SCAN tugmasi bilan local agentni ishga tushirish mumkin.'
