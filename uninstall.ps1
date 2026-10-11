# IP Shield — удаление с компьютера (PowerShell от администратора):
#   powershell -ExecutionPolicy Bypass -File C:\ProgramData\IPShield\uninstall.ps1
$ErrorActionPreference = 'Continue'
& schtasks.exe /Delete /TN 'IPShield-Agent' /F 2>$null | Out-Null
Get-NetFirewallRule -Name 'IPShield-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'IP Shield.lnk'
Remove-Item $lnk -Force -ErrorAction SilentlyContinue
$root = Join-Path $env:ProgramData 'IPShield'
Set-Location $env:SystemRoot
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'IP Shield удалён: задание, правила брандмауэра, ярлык и папка C:\ProgramData\IPShield.' -ForegroundColor Green
Write-Host 'Аудит неудачных входов оставлен включённым.'
