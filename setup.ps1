# IP Shield — установка и обновление на компьютере. Запускается из install.ps1 от администратора.
param(
    [string]$Token = '',
    [string]$Owner = 'xackustul-spec',
    [string]$CodeRepo = 'ip-shield',
    [string]$DataRepo = 'ip-shield-data',
    [string]$Branch = 'main'
)
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}

function Say([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'Нужно запустить PowerShell от имени администратора (заголовок окна начинается с «Администратор:»).' Red
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Say "Нужен PowerShell 5.1 или новее, здесь $($PSVersionTable.PSVersion). Установите Windows Management Framework 5.1." Red
    exit 1
}

$root = Join-Path $env:ProgramData 'IPShield'
Say "== IP Shield: установка в $root" Cyan
New-Item -ItemType Directory -Path $root -Force | Out-Null
# доступ к папке только у SYSTEM и администраторов — там лежит ключ GitHub
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# 1. файлы программы из публичного репозитория
$base = "https://raw.githubusercontent.com/$Owner/$CodeRepo/$Branch"
foreach ($f in 'common.ps1', 'agent.ps1', 'ui.ps1', 'uninstall.ps1') {
    $dst = Join-Path $root $f
    $wc = New-Object Net.WebClient
    $wc.Encoding = [Text.Encoding]::UTF8
    $txt = $wc.DownloadString("$base/$($f)?t=$([DateTime]::UtcNow.Ticks)")
    # сохраняем в UTF-8 с BOM, иначе PowerShell 5.1 исказит русский текст
    [IO.File]::WriteAllText("$dst.new", $txt.TrimStart([char]0xFEFF), (New-Object Text.UTF8Encoding($true)))
    Move-Item "$dst.new" $dst -Force
    Say "   скачан $dst"
}
. (Join-Path $root 'common.ps1')

# 2. настройки (ключ сохраняется; при повторной установке без ключа берётся старый)
$cfgPath = Join-Path $root 'config.json'
$cfg = Read-JsonFile $cfgPath @{}
if ($Token) { $cfg.token = $Token.Trim() }
if (-not $cfg.token) {
    $sec = Read-Host 'Вставьте ключ GitHub (github_pat_...) и нажмите Enter' -AsSecureString
    $cfg.token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)).Trim()
}
$cfg.owner = $Owner; $cfg.codeRepo = $CodeRepo; $cfg.dataRepo = $DataRepo; $cfg.branch = $Branch
Write-JsonFile $cfgPath $cfg
$cfg = Get-IPSConfig

# 3. проверка доступа к приватному репозиторию
try {
    [void](Get-GHTree $cfg)
    Say "   доступ к $Owner/$DataRepo есть" Green
} catch {
    Say "   НЕТ доступа к $Owner/$DataRepo : $($_.Exception.Message)" Red
    Say '   Проверьте ключ GitHub. Агент всё равно будет банить по местным журналам.' Yellow
}

# 4. убрать старый одиночный скрипт RDP-Ban, если был
& schtasks.exe /Delete /TN 'RDP-Ban' /F 2>$null | Out-Null
Get-NetFirewallRule -DisplayName 'RDP-Ban' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# 5. аудит неудачных входов (событие 4625)
& auditpol.exe /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /failure:enable | Out-Null
Say '   аудит неудачных входов включён'

# 6. локальная сеть — разрешить всё
$lan = @($cfg.lan)
if (Get-NetFirewallRule -Name 'IPShield-LAN' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'IPShield-LAN' -RemoteAddress $lan -Enabled True -Action Allow
} else {
    New-NetFirewallRule -Name 'IPShield-LAN' -DisplayName 'IP Shield - локальная сеть (всё разрешено)' -Direction Inbound -Action Allow -Profile Any -RemoteAddress $lan | Out-Null
}
Say "   локальная сеть $($lan -join ', ') разрешена во входящих"

$off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
if ($off.Count) { Say "   ВНИМАНИЕ: брандмауэр выключен для профилей: $($off -join ', '). Без него блокировки не работают." Yellow }

# 7. задание в Планировщике: агент каждую минуту от SYSTEM
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$tr = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$root\agent.ps1`""
& schtasks.exe /Create /TN 'IPShield-Agent' /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /TR $tr /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать задание IPShield-Agent в Планировщике' }
Say '   задание IPShield-Agent создано (каждую минуту)'

# 8. ярлык на общем рабочем столе, запуск от администратора
$lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'IP Shield.lnk'
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut($lnk)
$s.TargetPath = $ps
$s.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$root\ui.ps1`""
$s.IconLocation = "$env:SystemRoot\System32\shell32.dll,47"
$s.Description = 'IP Shield — мониторинг атак и блокировок'
$s.Save()
$bytes = [IO.File]::ReadAllBytes($lnk); $bytes[0x15] = $bytes[0x15] -bor 0x20; [IO.File]::WriteAllBytes($lnk, $bytes)
Say "   ярлык: $lnk"

# 9. первый запуск агента (читает журналы за последние дни — может занять минуту)
Say '   первый запуск агента...'
& $ps -NoProfile -ExecutionPolicy Bypass -File "$root\agent.ps1" -Force
$v = Read-JsonFile (Join-Path $root 'view.json') $null
if ($v) {
    Say ("== Готово. Атакующих IP: {0}, заблокировано: {1}." -f @($v.rows).Count, $v.bannedCount) Green
    foreach ($e in @($v.errors)) { if ($e) { Say "   ошибка: $e" Yellow } }
} else {
    Say "== Установлено, но агент не отработал. Смотрите журнал: $root\agent.log" Yellow
}
