# IP Shield — агент. Запускается Планировщиком каждую минуту от имени SYSTEM.
# 1) читает журналы Windows и находит неудачные входы с внешних IP;
# 2) раз в несколько минут обменивается данными с приватным репозиторием GitHub;
# 3) блокирует в брандмауэре IP, которые подбирали пароли здесь или на других компах.
param([switch]$Force)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$mutex = New-Object System.Threading.Mutex($false, 'Global\IPShieldAgent')
if (-not $mutex.WaitOne(0)) { exit 0 }

# ---------------- сбор событий ----------------
function Get-RdpPort {
    try { return [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber }
    catch { return 3389 }
}

function Get-NewEvents([hashtable]$State, [string]$Key, [hashtable]$Filter) {
    $events = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    $last = [int64]0
    if ($State.rec[$Key]) { $last = [int64]$State.rec[$Key] }
    if ($events.Count -eq 0) { return @() }
    $top = [int64]($events | Measure-Object -Property RecordId -Maximum).Maximum
    if ($top -lt $last) { $last = 0 }          # журнал очистили — начинаем заново
    $State.rec[$Key] = [string]([math]::Max($top, $last))
    return @($events | Where-Object { [int64]$_.RecordId -gt $last } | Sort-Object RecordId)
}

function Get-EventData($Event) {
    $d = @{}
    try { foreach ($n in ([xml]$Event.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } } catch {}
    return $d
}

function Get-Attempts([hashtable]$State, [datetime]$Since) {
    $out = New-Object System.Collections.ArrayList
    $rdpPort = Get-RdpPort
    $rdpSeen = @{}

    # RDP: «Не удалось подключить клиентский компьютер с IP-адресом ...»
    foreach ($e in (Get-NewEvents $State 'rdp' @{ LogName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id = 140; StartTime = $Since })) {
        $ip = (Get-EventData $e)['IPString']
        if (-not $ip -and $e.Message -match '(\d{1,3}(\.\d{1,3}){3})') { $ip = $Matches[1] }
        $ip = Get-NormalIP $ip
        if (-not $ip) { continue }
        $t = $e.TimeCreated.ToUniversalTime()
        [void]$out.Add(@{ ip = $ip; time = $t; svc = "RDP:$rdpPort"; user = $null; cnt = $true })
        if (-not $rdpSeen[$ip]) { $rdpSeen[$ip] = New-Object System.Collections.ArrayList }
        [void]$rdpSeen[$ip].Add($t)
    }

    # Windows: неудачный вход (4625) — SMB, RDP, веб и т.д.
    foreach ($e in (Get-NewEvents $State 'sec' @{ LogName = 'Security'; Id = 4625; StartTime = $Since })) {
        $d = Get-EventData $e
        $ip = Get-NormalIP $d['IpAddress']
        if (-not $ip) { continue }
        $t = $e.TimeCreated.ToUniversalTime()
        $user = $d['TargetUserName']
        $dup = $false
        if ($rdpSeen[$ip]) { foreach ($rt in $rdpSeen[$ip]) { if ([math]::Abs(($rt - $t).TotalSeconds) -le 5) { $dup = $true; break } } }
        if ($dup) {
            [void]$out.Add(@{ ip = $ip; time = $t; svc = "RDP:$rdpPort"; user = $user; cnt = $false })
            continue
        }
        $svc = switch ([string]$d['LogonType']) {
            '10'    { "RDP:$rdpPort" }
            '3'     { 'Сеть/SMB:445' }
            '8'     { 'Веб (Basic):80/443' }
            default { "Вход Windows (тип $($d['LogonType']))" }
        }
        [void]$out.Add(@{ ip = $ip; time = $t; svc = $svc; user = $user; cnt = $true })
    }

    # MS SQL Server: 18456 «Login failed ... [CLIENT: x.x.x.x]»
    foreach ($e in (Get-NewEvents $State 'sql' @{ LogName = 'Application'; Id = 18456; StartTime = $Since })) {
        if ($e.Message -notmatch 'CLIENT:\s*([\d\.]+)') { continue }
        $ip = Get-NormalIP $Matches[1]
        if (-not $ip) { continue }
        $user = $null
        if ($e.Message -match "(?:user|пользователя)\s+[`"'«]([^`"'»]+)") { $user = $Matches[1] }
        [void]$out.Add(@{ ip = $ip; time = $e.TimeCreated.ToUniversalTime(); svc = 'MS SQL:1433'; user = $user; cnt = $true })
    }

    # OpenSSH для Windows
    foreach ($e in (Get-NewEvents $State 'ssh' @{ LogName = 'OpenSSH/Operational'; StartTime = $Since })) {
        if ($e.Message -match '(?:Failed \S+ for (?:invalid user )?(\S+)|Invalid user (\S+)) from (\d{1,3}(?:\.\d{1,3}){3})') {
            $ip = Get-NormalIP $Matches[3]
            if (-not $ip) { continue }
            $user = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            [void]$out.Add(@{ ip = $ip; time = $e.TimeCreated.ToUniversalTime(); svc = 'SSH:22'; user = $user; cnt = $true })
        }
    }
    return ,$out
}

# IP, с которых был успешный вход по RDP (свои) — их не блокируем, чтобы не отрезать себя.
function Get-TrustedIPs([int]$Days) {
    $set = @{}
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue)
    foreach ($e in $ev) {
        try {
            $ip = Get-NormalIP ([string]([xml]$e.ToXml()).Event.UserData.EventXML.Param3)
            if ($ip -and -not (Test-PrivateIP $ip)) {
                $s = Get-Stamp $e.TimeCreated
                if (-not $set[$ip] -or $set[$ip] -lt $s) { $set[$ip] = $s }
            }
        } catch {}
    }
    return $set
}

# ---------------- страна по IP (ip-api.com, бесплатно) ----------------
function Update-Geo([hashtable]$Attackers) {
    $need = @($Attackers.Keys | Where-Object { -not $Attackers[$_].cc } | Select-Object -First 100)
    if ($need.Count -eq 0) { return }
    try {
        $body = ConvertTo-Json -InputObject @($need) -Compress
        $r = Invoke-RestMethod -Uri 'http://ip-api.com/batch?fields=status,query,country,countryCode&lang=ru' -Method Post `
                -Body $body -ContentType 'application/json' -TimeoutSec 20 -UseBasicParsing
        foreach ($g in $r) {
            $a = $Attackers[[string]$g.query]
            if (-not $a) { continue }
            if ($g.status -eq 'success') { $a.cc = [string]$g.countryCode; $a.co = [string]$g.country }
            else { $a.cc = '-'; $a.co = 'неизвестно' }
        }
    } catch { Write-IPSLog "GeoIP: $($_.Exception.Message)" }
}

# ---------------- брандмауэр ----------------
function Set-BanRules([string[]]$Ips) {
    $chunks = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Ips.Count; $i += 1000) {
        [void]$chunks.Add([string[]]$Ips[$i..([math]::Min($i + 999, $Ips.Count - 1))])
    }
    $existing = @(Get-NetFirewallRule -Name 'IPShield-Ban-*' -ErrorAction SilentlyContinue)
    for ($k = 0; $k -lt $chunks.Count; $k++) {
        $name = "IPShield-Ban-$k"
        if ($existing | Where-Object { $_.Name -eq $name }) {
            Set-NetFirewallRule -Name $name -RemoteAddress $chunks[$k] -Enabled True -Action Block
        } else {
            New-NetFirewallRule -Name $name -DisplayName "IP Shield - блокировка $k" -Description 'Создано IP Shield. Не редактировать вручную.' `
                -Direction Inbound -Action Block -Profile Any -RemoteAddress $chunks[$k] | Out-Null
        }
    }
    foreach ($r in $existing) {
        $idx = [int]($r.Name -replace '^IPShield-Ban-', '')
        if ($idx -ge $chunks.Count) { Remove-NetFirewallRule -Name $r.Name }
    }
}

# ---------------- основной проход ----------------
$cfg = Get-IPSConfig
if (-not $cfg) { Write-IPSLog 'Нет config.json — агент не настроен'; exit 1 }

$now = Get-Date
$nowS = Get-Stamp $now
$state = Read-JsonFile $IPS_StatePath @{}
foreach ($k in 'attackers', 'rec') { if (-not ($state[$k] -is [System.Collections.IDictionary])) { $state[$k] = @{} } }
if ($null -eq $state['applied']) { $state['applied'] = @() }
$Att = $state.attackers
$errors = New-Object System.Collections.ArrayList

# 1. новые события
try {
    $since = if ($state.lastScan) { (ConvertFrom-Stamp $state.lastScan).AddMinutes(-30) } else { $now.AddDays(-[int]$cfg.windowDays) }
    $attempts = Get-Attempts $state $since
    foreach ($x in $attempts) {
        if (Test-PrivateIP $x.ip) { continue }
        $s = Get-Stamp $x.time
        $a = $Att[$x.ip]
        if (-not $a) { $a = @{ c = 0; f = $s; l = $s; s = @{}; u = @(); r = @() }; $Att[$x.ip] = $a }
        if ($x.user -and -not (@($a.u) -contains $x.user) -and @($a.u).Count -lt 15) { $a.u = @($a.u) + $x.user }
        if (-not $x.cnt) { continue }
        $a.c = [int]$a.c + 1
        if ($s -lt $a.f) { $a.f = $s }
        if ($s -gt $a.l) { $a.l = $s }
        if (-not ($a.s -is [System.Collections.IDictionary])) { $a.s = @{} }
        $a.s[$x.svc] = [int]$a.s[$x.svc] + 1
        $a.r = @(@($a.r) + $s | Select-Object -Last 200)
    }
    $state.lastScan = $nowS
    if ($attempts.Count -gt 0) { Write-IPSLog "Новых событий: $($attempts.Count)" }
} catch { [void]$errors.Add("Журналы: $($_.Exception.Message)"); Write-IPSLog "Ошибка чтения журналов: $($_.Exception.Message)" }

# чистим старьё
$keepS = Get-Stamp $now.AddDays(-[int]$cfg.keepDays)
$winS = Get-Stamp $now.AddDays(-[int]$cfg.windowDays)
foreach ($ip in @($Att.Keys)) {
    if ($Att[$ip].l -lt $keepS) { $Att.Remove($ip); continue }
    $Att[$ip].r = @(@($Att[$ip].r) | Where-Object { $_ -ge $winS })
}

Update-Geo $Att

# 2. общий список из GitHub
$shared = Read-JsonFile $IPS_SharedPath @{}
if (-not ($shared['files'] -is [System.Collections.IDictionary])) { $shared['files'] = @{} }
$tree = $null
$force = $Force -or (Test-Path $IPS_ForceFlag)
$syncDue = $force -or -not $state.lastSync -or ($state.lastSync -lt (Get-Stamp $now.AddMinutes(-[int]$cfg.syncMinutes)))
if ($syncDue -and $cfg.token) {
    try {
        $tree = Get-GHTree $cfg
        foreach ($path in @($tree.Keys)) {
            if ($path -ne 'control.json' -and $path -notlike 'hosts/*.json') { continue }
            $cached = $shared.files[$path]
            if ($cached -and $cached.sha -eq $tree[$path]) { continue }
            $data = ConvertFrom-JsonHT (Get-GHBlobText $cfg $tree[$path])
            $shared.files[$path] = @{ sha = $tree[$path]; data = $data }
        }
        foreach ($path in @($shared.files.Keys)) { if (-not $tree.ContainsKey($path)) { $shared.files.Remove($path) } }
        $state.lastSync = $nowS
        if (Test-Path $IPS_ForceFlag) { Remove-Item $IPS_ForceFlag -Force -ErrorAction SilentlyContinue }
    } catch { [void]$errors.Add("GitHub (чтение): $($_.Exception.Message)"); Write-IPSLog "GitHub чтение: $($_.Exception.Message)" }
}

$ctl = Initialize-Control $(if ($shared.files['control.json']) { $shared.files['control.json'].data } else { $null })
$white = @($ctl.whitelist)
$unban = $ctl.unban

# 3. решаем, кого банить по местным событиям
$trusted = Get-TrustedIPs ([int]$cfg.trustDays)
$threshold = [int]$cfg.threshold
foreach ($ip in @($Att.Keys)) {
    $a = $Att[$ip]
    $from = $winS
    if ($unban[$ip] -and [string]$unban[$ip] -gt $from) { $from = [string]$unban[$ip] }
    $recent = @(@($a.r) | Where-Object { $_ -gt $from }).Count
    $a.b = ($recent -ge $threshold)
}

# 4. отправляем свой файл в общий репозиторий
$me = $env:COMPUTERNAME
$myPath = "hosts/$me.json"
$lanIp = $null
try { $lanIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress } catch {}
$fwOn = $null
try { $fwOn = -not @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count } catch {}
$pubA = @{}
foreach ($ip in $Att.Keys) {
    $a = $Att[$ip]
    $pubA[$ip] = @{ c = $a.c; f = $a.f; l = $a.l; s = $a.s; u = @($a.u); cc = $a.cc; co = $a.co; b = [bool]$a.b }
}
$hostDoc = @{ host = $me; lan = $lanIp; version = $IPS_Version; firewall = $fwOn; attackers = $pubA; trusted = $trusted }
$hash = [BitConverter]::ToString((New-Object Security.Cryptography.SHA1Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonText $hostDoc))))
$newBan = @($Att.Keys | Where-Object { $Att[$_].b -and -not (@($state.lastPushedBans) -contains $_) }).Count -gt 0
$pushDue = ($hash -ne $state.lastHash -and ($newBan -or $force -or -not $state.lastPush -or $state.lastPush -lt (Get-Stamp $now.AddMinutes(-[int]$cfg.pushMinutes)))) `
           -or (-not $state.lastPush) -or ($state.lastPush -lt (Get-Stamp $now.AddHours(-6)))
if ($pushDue -and $cfg.token -and $tree) {
    try {
        $hostDoc.updated = $nowS
        $sha = Set-GHFile $cfg $myPath (ConvertTo-JsonText $hostDoc) $tree[$myPath] "$me`: обновление списка атак"
        $shared.files[$myPath] = @{ sha = $sha; data = (ConvertFrom-JsonHT (ConvertTo-JsonText $hostDoc)) }
        $state.lastPush = $nowS; $state.lastHash = $hash
        $state.lastPushedBans = @($Att.Keys | Where-Object { $Att[$_].b })
    } catch {
        $code = Get-HttpStatus $_
        if ($code -eq 409 -or $code -eq 422) { $state.lastSync = $null }   # sha устарел — перечитаем в следующий раз
        [void]$errors.Add("GitHub (запись): $($_.Exception.Message)"); Write-IPSLog "GitHub запись: $($_.Exception.Message)"
    }
}

# 5. сводим всё вместе: свои данные + данные всех компов
$rows = @{}
$trustAll = @{}
$hostsInfo = New-Object System.Collections.ArrayList
$docs = @{}
foreach ($path in $shared.files.Keys) { if ($path -like 'hosts/*.json') { $docs[$path] = $shared.files[$path].data } }
$hostDoc.updated = $nowS
$docs[$myPath] = $hostDoc       # своё — всегда самое свежее
foreach ($path in $docs.Keys) {
    $d = $docs[$path]
    if (-not ($d -is [System.Collections.IDictionary])) { continue }
    $h = [string]$d.host
    [void]$hostsInfo.Add(@{ host = $h; lan = $d.lan; version = $d.version; updated = $d.updated; firewall = $d.firewall
                            attackers = @($d.attackers.Keys).Count; banned = @($d.attackers.Keys | Where-Object { $d.attackers[$_].b }).Count })
    if ($d.trusted -is [System.Collections.IDictionary]) { foreach ($ip in $d.trusted.Keys) { $trustAll[$ip] = $h } }
    if (-not ($d.attackers -is [System.Collections.IDictionary])) { continue }
    foreach ($ip in $d.attackers.Keys) {
        $a = $d.attackers[$ip]
        $r = $rows[$ip]
        if (-not $r) { $r = @{ ip = $ip; c = 0; f = $a.f; l = $a.l; s = @{}; u = @(); hosts = @(); cc = $null; co = $null; banned = $false }; $rows[$ip] = $r }
        $r.c += [int]$a.c
        if ($a.f -and $a.f -lt $r.f) { $r.f = $a.f }
        if ($a.l -and $a.l -gt $r.l) { $r.l = $a.l }
        if ($a.s -is [System.Collections.IDictionary]) { foreach ($k in $a.s.Keys) { $r.s[$k] = [int]$r.s[$k] + [int]$a.s[$k] } }
        foreach ($u in @($a.u)) { if ($u -and -not (@($r.u) -contains $u) -and @($r.u).Count -lt 15) { $r.u = @($r.u) + $u } }
        $r.hosts = @($r.hosts) + $h
        if (-not $r.cc -and $a.cc) { $r.cc = $a.cc; $r.co = $a.co }
        $ub = [string]$unban[$ip]
        if ($a.b -and (-not $ub -or [string]$a.l -gt $ub)) { $r.banned = $true }
    }
}

# 6. итоговый список блокировок
$desired = New-Object System.Collections.ArrayList
foreach ($ip in $rows.Keys) {
    $r = $rows[$ip]
    if (Test-PrivateIP $ip) { $r.status = 'Локальный'; continue }
    if (Test-IPInList $ip $white) { $r.status = 'Исключение'; continue }
    if ($trustAll[$ip]) { $r.status = "Свой (успешный вход на $($trustAll[$ip]))"; continue }
    if ($r.banned) { $r.status = 'Забанен'; [void]$desired.Add($ip); continue }
    if ($unban[$ip]) { $r.status = 'Разбанен'; continue }
    $r.status = 'Наблюдение'
}
$desiredSorted = @($desired | Sort-Object { Get-IPNum $_ })
if (($desiredSorted -join ',') -ne (@($state.applied) -join ',')) {
    try {
        Set-BanRules $desiredSorted
        $added = @($desiredSorted | Where-Object { -not (@($state.applied) -contains $_) })
        $removed = @(@($state.applied) | Where-Object { -not ($desiredSorted -contains $_) })
        Write-IPSLog "Брандмауэр: заблокировано $($desiredSorted.Count) (+$($added.Count) / -$($removed.Count)) $(($added | Select-Object -First 10) -join ' ')"
        $state.applied = $desiredSorted
    } catch { [void]$errors.Add("Брандмауэр: $($_.Exception.Message)"); Write-IPSLog "Брандмауэр: $($_.Exception.Message)" }
}

# 7. данные для окна мониторинга
$view = @{
    host = $me; version = $IPS_Version; generated = $nowS; lastScan = $state.lastScan; lastSync = $state.lastSync; lastPush = $state.lastPush
    firewall = $fwOn; bannedCount = $desiredSorted.Count; errors = @($errors); threshold = $threshold; windowDays = [int]$cfg.windowDays
    rows = @($rows.Values); whitelist = @($white); unban = $unban; hosts = @($hostsInfo)
}
try { Write-JsonFile $IPS_ViewPath $view } catch { Write-IPSLog "view.json: $($_.Exception.Message)" }
$state.lastErrors = @($errors)
Write-JsonFile $IPS_SharedPath $shared
Write-JsonFile $IPS_StatePath $state
$mutex.ReleaseMutex()
