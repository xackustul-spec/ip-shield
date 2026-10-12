# IP Shield — окно мониторинга (ярлык «IP Shield» на рабочем столе, запуск от администратора)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

$cfg = Get-IPSConfig
if (-not $cfg) {
    [System.Windows.Forms.MessageBox]::Show("IP Shield не настроен: нет файла $IPS_ConfigPath.`nЗапустите установку заново.", 'IP Shield') | Out-Null
    exit 1
}

function Show-Error([string]$Text) { [System.Windows.Forms.MessageBox]::Show($Text, 'IP Shield', 'OK', 'Error') | Out-Null }
function Ask-Text([string]$Prompt, [string]$Default = '') { return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, 'IP Shield', $Default) }
function Format-Local([string]$Stamp) { if (-not $Stamp) { return '' }; return (ConvertFrom-Stamp $Stamp).ToLocalTime().ToString('dd.MM.yyyy HH:mm') }

# Записать изменение в общий control.json и сразу запустить агента
function Invoke-ControlChange([scriptblock]$Mutator, [string]$Message) {
    $form.Cursor = 'WaitCursor'
    try {
        [void](Update-Control $cfg $Mutator $Message)
        New-Item -ItemType File -Path $IPS_ForceFlag -Force | Out-Null
        try { Start-ScheduledTask -TaskName 'IPShield-Agent' } catch { & schtasks.exe /Run /TN 'IPShield-Agent' | Out-Null }
        $statusLabel.Text = 'Изменение сохранено. Агент применит его в течение минуты, на других компах — в течение 5 минут.'
        $timerFast.Start()
    } catch {
        Show-Error "Не удалось сохранить изменение в GitHub:`n$($_.Exception.Message)"
    } finally { $form.Cursor = 'Default' }
}

# ---------------- форма ----------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "IP Shield — $env:COMPUTERNAME"
$form.Size = New-Object System.Drawing.Size(1280, 760)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$top = New-Object System.Windows.Forms.Label
$top.Dock = 'Top'; $top.Height = 44; $top.Padding = (New-Object System.Windows.Forms.Padding(8,6,8,0))
$top.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.Controls.Add($top)

$status = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Spring = $true; $statusLabel.TextAlign = 'MiddleLeft'
[void]$status.Items.Add($statusLabel)
$form.Controls.Add($status)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)
$tabs.BringToFront()

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'; $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false
    $g.SelectionMode = 'FullRowSelect'; $g.MultiSelect = $true; $g.RowHeadersVisible = $false
    $g.AutoSizeColumnsMode = 'Fill'; $g.BackgroundColor = [System.Drawing.Color]::White
    return $g
}

function New-ButtonBar([object[]]$Buttons) {
    $p = New-Object System.Windows.Forms.FlowLayoutPanel
    $p.Dock = 'Top'; $p.Height = 38; $p.Padding = (New-Object System.Windows.Forms.Padding(4,4,4,0))
    foreach ($b in $Buttons) { $p.Controls.Add($b) }
    return $p
}

function New-Btn([string]$Text, [int]$Width = 150) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Width = $Width; $b.Height = 28
    return $b
}

# ---- вкладка «Атаки» ----
$tabA = New-Object System.Windows.Forms.TabPage; $tabA.Text = 'Атаки'
$tblA = New-Object System.Data.DataTable
foreach ($c in @(@('IP', [string]), @('Страна', [string]), @('Службы (порт)', [string]), @('Попыток', [int]),
                 @('Первая', [datetime]), @('Последняя', [datetime]), @('Компьютеры', [string]), @('Логины', [string]), @('Статус', [string]), @('Причина', [string]))) {
    [void]$tblA.Columns.Add($c[0], $c[1])
}
$gridA = New-Grid
$gridA.DataSource = $tblA
$filter = New-Object System.Windows.Forms.TextBox; $filter.Width = 220
$filterLbl = New-Object System.Windows.Forms.Label; $filterLbl.Text = 'Поиск:'; $filterLbl.AutoSize = $true; $filterLbl.Padding = (New-Object System.Windows.Forms.Padding(10,7,0,0))
$onlyBanned = New-Object System.Windows.Forms.CheckBox; $onlyBanned.Text = 'Только забаненные'; $onlyBanned.AutoSize = $true; $onlyBanned.Padding = (New-Object System.Windows.Forms.Padding(10,4,0,0))
$bUnban = New-Btn 'Разбанить'
$bWhite = New-Btn 'В исключения'
$bRefresh = New-Btn 'Обновить' 110
$bExport = New-Btn 'Выгрузить забаненные' 170
$tabA.Controls.Add($gridA)
$tabA.Controls.Add((New-ButtonBar @($bUnban, $bWhite, $bExport, $bRefresh, $filterLbl, $filter, $onlyBanned)))
$tabs.TabPages.Add($tabA)

# ---- вкладка «Исключения» ----
$tabW = New-Object System.Windows.Forms.TabPage; $tabW.Text = 'Исключения'
$tblW = New-Object System.Data.DataTable
foreach ($c in 'IP или подсеть', 'Заметка', 'Добавил', 'Когда') { [void]$tblW.Columns.Add($c, [string]) }
$gridW = New-Grid; $gridW.DataSource = $tblW
$bWAdd = New-Btn 'Добавить IP / подсеть' 170
$bWDel = New-Btn 'Убрать из исключений' 170
$bMyIp = New-Btn 'Добавить мой текущий IP' 190
$tabW.Controls.Add($gridW)
$tabW.Controls.Add((New-ButtonBar @($bWAdd, $bMyIp, $bWDel)))
$tabs.TabPages.Add($tabW)

# ---- вкладка «Компьютеры» ----
$tabH = New-Object System.Windows.Forms.TabPage; $tabH.Text = 'Компьютеры'
$tblH = New-Object System.Data.DataTable
foreach ($c in 'Компьютер', 'IP в локалке', 'Версия', 'Последняя связь', 'Брандмауэр', 'Атакующих IP', 'Забанил сам') { [void]$tblH.Columns.Add($c, [string]) }
$gridH = New-Grid; $gridH.DataSource = $tblH
$tabH.Controls.Add($gridH)
$tabs.TabPages.Add($tabH)

# ---- вкладка «Журнал» ----
$tabL = New-Object System.Windows.Forms.TabPage; $tabL.Text = 'Журнал агента'
$log = New-Object System.Windows.Forms.TextBox
$log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = 'Both'; $log.Dock = 'Fill'; $log.WordWrap = $false
$log.Font = New-Object System.Drawing.Font('Consolas', 9)
$tabL.Controls.Add($log)
$tabs.TabPages.Add($tabL)

# ---------------- данные ----------------
$script:view = $null
function Update-Filter {
    $t = $filter.Text.Replace("'", "''").Replace('[', '[[]').Replace('%', '[%]').Replace('*', '[*]')
    $parts = @()
    if ($t) { $parts += "(IP LIKE '%$t%' OR [Страна] LIKE '%$t%' OR [Службы (порт)] LIKE '%$t%' OR [Компьютеры] LIKE '%$t%' OR [Логины] LIKE '%$t%' OR [Статус] LIKE '%$t%' OR [Причина] LIKE '%$t%')" }
    if ($onlyBanned.Checked) { $parts += "[Статус] = 'Забанен'" }
    $tblA.DefaultView.RowFilter = ($parts -join ' AND ')
}

function Import-View {
    $v = Read-JsonFile $IPS_ViewPath $null
    if (-not $v) { $top.Text = 'Данных пока нет: агент ещё не отработал. Подождите минуту и нажмите «Обновить».'; return }
    $script:view = $v

    $selected = @($gridA.SelectedRows | ForEach-Object { $_.Cells['IP'].Value })
    $tblA.BeginLoadData(); $tblA.Clear()
    foreach ($r in @($v.rows)) {
        if (-not $r) { continue }
        $svc = (@($r.s.Keys | Sort-Object { -[int]$r.s[$_] } | ForEach-Object { "$_ ($($r.s[$_]))" }) -join ', ')
        $hosts = (@($r.hosts) | Sort-Object -Unique) -join ', '
        $country = if ($r.co) { "$($r.co) ($($r.cc))" } else { '' }
        $first = if ($r.f) { (ConvertFrom-Stamp $r.f).ToLocalTime() } else { [DBNull]::Value }
        $last = if ($r.l) { (ConvertFrom-Stamp $r.l).ToLocalTime() } else { [DBNull]::Value }
        [void]$tblA.Rows.Add($r.ip, $country, $svc, [int]$r.c, $first, $last, $hosts, ((@($r.u)) -join ', '), $r.status, [string]$r.why)
    }
    $tblA.EndLoadData()
    if (-not $gridA.SortedColumn) { $tblA.DefaultView.Sort = '[Последняя] DESC' }
    Update-Filter
    foreach ($row in $gridA.Rows) { $row.Selected = ($selected -contains $row.Cells['IP'].Value) }

    $tblW.Clear()
    foreach ($w in @($v.whitelist)) {
        if (-not $w) { continue }
        if ($w -is [System.Collections.IDictionary]) { [void]$tblW.Rows.Add($w.ip, $w.note, $w.by, (Format-Local $w.added)) }
        else { [void]$tblW.Rows.Add([string]$w, '', '', '') }
    }

    $tblH.Clear()
    foreach ($h in @($v.hosts | Sort-Object { $_.host })) {
        if (-not $h) { continue }
        $fw = if ($h.firewall -eq $true) { 'включён' } elseif ($h.firewall -eq $false) { 'ВЫКЛЮЧЕН' } else { '?' }
        [void]$tblH.Rows.Add($h.host, $h.lan, $h.version, (Format-Local $h.updated), $fw, [string]$h.attackers, [string]$h.banned)
    }

    $fwText = if ($v.firewall -eq $false) { '   БРАНДМАУЭР ВЫКЛЮЧЕН — блокировки не работают!' } else { '' }
    $top.Text = "Компьютер: $($v.host)   |   Заблокировано IP: $($v.bannedCount)   |   Атакующих IP: $(@($v.rows).Count)   |   " +
                "Правило бана: $($v.threshold) неудачных попыток за $($v.windowDays) дн.$fwText`n" +
                "Проверка журналов: $(Format-Local $v.lastScan)   |   Обмен с GitHub: $(Format-Local $v.lastSync)   |   Версия $($v.version)"
    if (@($v.errors).Count -gt 0) { $top.ForeColor = 'DarkRed'; $statusLabel.Text = 'Ошибки: ' + (@($v.errors) -join ' | ') }
    else { $top.ForeColor = 'Black' }
    if ($v.firewall -eq $false) { $top.ForeColor = 'DarkRed' }

    try { if (Test-Path $IPS_LogPath) { $log.Lines = @(Get-Content $IPS_LogPath -Tail 300 -Encoding UTF8); $log.SelectionStart = $log.TextLength; $log.ScrollToCaret() } } catch {}
}

$gridA.add_CellFormatting({
    param($s, $e)
    if ($e.RowIndex -lt 0) { return }
    $st = [string]$gridA.Rows[$e.RowIndex].Cells['Статус'].Value
    $color = if ($st -eq 'Забанен') { 'MistyRose' } elseif ($st -eq 'Исключение') { 'Honeydew' } elseif ($st -like 'Свой*') { 'AliceBlue' } elseif ($st -eq 'Разбанен') { 'LightYellow' } else { 'White' }
    $e.CellStyle.BackColor = [System.Drawing.Color]::FromName($color)
})
$gridA.add_DataBindingComplete({
    foreach ($n in 'Первая', 'Последняя') { if ($gridA.Columns[$n]) { $gridA.Columns[$n].DefaultCellStyle.Format = 'dd.MM.yyyy HH:mm' } }
    if ($gridA.Columns['Службы (порт)']) { $gridA.Columns['Службы (порт)'].FillWeight = 160 }
    if ($gridA.Columns['Логины']) { $gridA.Columns['Логины'].FillWeight = 140 }
    if ($gridA.Columns['Статус']) { $gridA.Columns['Статус'].FillWeight = 130 }
    if ($gridA.Columns['Причина']) { $gridA.Columns['Причина'].FillWeight = 260 }
})

function Get-SelectedIPs { return @($gridA.SelectedRows | ForEach-Object { [string]$_.Cells['IP'].Value } | Where-Object { $_ }) }


# Выгрузка забаненных IP: HTML-отчёт + TXT-список (по одному IP в строке) на рабочий стол
function Export-Banned {
    $v = $script:view
    if (-not $v) { Show-Error 'Нет данных: подождите, пока агент отработает.'; return }
    $rows = @($v.rows | Where-Object { $_ -and $_.status -eq 'Забанен' } | Sort-Object { -[int]$_.c })
    if ($rows.Count -eq 0) { Show-Error 'Забаненных IP пока нет.'; return }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $rows) {
        $svc = (@($r.s.Keys | Sort-Object { -[int]$r.s[$_] } | ForEach-Object { "$_ ($($r.s[$_]))" }) -join ', ')
        $country = if ($r.co) { "$($r.co) ($($r.cc))" } else { '' }
        [void]$sb.Append("<tr><td>$(& $enc $r.ip)</td><td>$(& $enc $country)</td><td>$(& $enc $svc)</td><td class=n>$([int]$r.c)</td>" +
            "<td>$(Format-Local $r.f)</td><td>$(Format-Local $r.l)</td><td>$(& $enc ((@($r.hosts) | Sort-Object -Unique) -join ', '))</td><td>$(& $enc ((@($r.u)) -join ', '))</td><td>$(& $enc $r.why)</td></tr>`n")
    }
    $when = (Get-Date).ToString('dd.MM.yyyy HH:mm')
    $html = @"
<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>IP Shield — заблокированные IP</title>
<style>
body{font:14px Segoe UI,Arial,sans-serif;margin:24px;color:#222}h1{font-size:20px;margin:0 0 4px}.m{color:#666;margin-bottom:16px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f3f3f3;cursor:pointer;position:sticky;top:0}tr:nth-child(even){background:#fafafa}td.n{text-align:right}
input{padding:6px 8px;width:280px;margin-bottom:10px}
</style></head><body>
<h1>IP Shield — заблокированные IP</h1>
<div class="m">Компьютер: $(& $enc $v.host) · выгружено $when · всего: $($rows.Count) · правило: $($v.threshold) неудачных попыток за $($v.windowDays) дн.</div>
<input id="q" placeholder="Поиск..." oninput="f()">
<table id="t"><thead><tr><th>IP</th><th>Страна</th><th>Службы (порт)</th><th>Попыток</th><th>Первая</th><th>Последняя</th><th>Компьютеры</th><th>Логины</th><th>Причина бана</th></tr></thead><tbody>
$($sb.ToString())</tbody></table>
<script>
function f(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#t tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(q)>=0?'':'none'})}
document.querySelectorAll('#t th').forEach(function(th,i){th.onclick=function(){var b=document.querySelector('#t tbody'),rs=[].slice.call(b.rows),d=th.dataset.d=th.dataset.d==='1'?'0':'1';
rs.sort(function(a,c){var x=a.cells[i].innerText,y=c.cells[i].innerText;if(i===3){x=+x;y=+y}else if(i===4||i===5){x=x.split(/[. :]/);x=x[2]+x[1]+x[0]+x[3]+x[4];y=y.split(/[. :]/);y=y[2]+y[1]+y[0]+y[3]+y[4]}return (x>y?1:x<y?-1:0)*(d==='1'?1:-1)});rs.forEach(function(r){b.appendChild(r)})}})
</script></body></html>
"@
    $desk = [Environment]::GetFolderPath('Desktop')
    if (-not $desk) { $desk = $env:TEMP }
    $stamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm')
    $htmlPath = Join-Path $desk "IP Shield - заблокированные $stamp.html"
    $txtPath = Join-Path $desk "IP Shield - заблокированные $stamp.txt"
    [IO.File]::WriteAllText($htmlPath, $html, (New-Object Text.UTF8Encoding($true)))
    [IO.File]::WriteAllLines($txtPath, [string[]]@($rows | ForEach-Object { $_.ip }), (New-Object Text.UTF8Encoding($false)))
    $statusLabel.Text = "Выгружено $($rows.Count) IP: $htmlPath и $txtPath"
    Start-Process $htmlPath
}

# ---------------- кнопки ----------------
$bRefresh.add_Click({ Import-View })
$bExport.add_Click({ try { Export-Banned } catch { Show-Error "Не удалось выгрузить: $($_.Exception.Message)" } })
$filter.add_TextChanged({ Update-Filter })
$onlyBanned.add_CheckedChanged({ Update-Filter })

$bUnban.add_Click({
    $ips = Get-SelectedIPs
    if ($ips.Count -eq 0) { Show-Error 'Выделите строки с IP, которые нужно разбанить.'; return }
    $ok = [System.Windows.Forms.MessageBox]::Show("Разбанить на ВСЕХ компьютерах:`n$($ips -join "`n")`n`nЕсли с адреса снова начнут подбирать пароль, он будет забанен опять.", 'IP Shield', 'YesNo', 'Question')
    if ($ok -ne 'Yes') { return }
    $stamp = Get-Stamp
    Invoke-ControlChange { param($c) foreach ($ip in $ips) { $c.unban[$ip] = $stamp } }.GetNewClosure() "$env:COMPUTERNAME`: разбан $($ips -join ', ')"
})

function Add-Whitelist([string[]]$Entries, [string]$Note) {
    $bad = @($Entries | Where-Object { -not (Test-IPEntry $_) })
    if ($bad.Count) { Show-Error "Неверный адрес: $($bad -join ', ')`nПример: 77.51.218.161 или 77.51.218.0/24"; return }
    $stamp = Get-Stamp; $by = $env:COMPUTERNAME
    Invoke-ControlChange {
        param($c)
        foreach ($ip in $Entries) {
            if (@($c.whitelist | Where-Object { ($(if ($_ -is [System.Collections.IDictionary]) { $_.ip } else { $_ })) -eq $ip }).Count -eq 0) {
                $c.whitelist = @($c.whitelist) + @{ ip = $ip; note = $Note; by = $by; added = $stamp }
            }
        }
    }.GetNewClosure() "$($by): исключение $($Entries -join ', ')"
}

$bWhite.add_Click({
    $ips = Get-SelectedIPs
    if ($ips.Count -eq 0) { Show-Error 'Выделите строки с IP, которые нужно добавить в исключения.'; return }
    $note = Ask-Text "Заметка для исключения (кто это):`n$($ips -join ', ')"
    Add-Whitelist $ips $note
})

$bWAdd.add_Click({
    $ip = (Ask-Text 'IP или подсеть, например 77.51.218.161 или 77.51.218.0/24:').Trim()
    if (-not $ip) { return }
    $note = Ask-Text 'Заметка (кто это):'
    Add-Whitelist @($ip) $note
})

$bMyIp.add_Click({
    try { $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 15).ToString().Trim() }
    catch { Show-Error "Не удалось узнать внешний IP: $($_.Exception.Message)"; return }
    $note = Ask-Text "Внешний IP этой сети: $ip`nЗаметка (например «Офис VSPORTE»):"
    Add-Whitelist @($ip) $note
})

$bWDel.add_Click({
    $sel = @($gridW.SelectedRows | ForEach-Object { [string]$_.Cells['IP или подсеть'].Value } | Where-Object { $_ })
    if ($sel.Count -eq 0) { Show-Error 'Выделите строки, которые нужно убрать из исключений.'; return }
    $ok = [System.Windows.Forms.MessageBox]::Show("Убрать из исключений на ВСЕХ компьютерах:`n$($sel -join "`n")", 'IP Shield', 'YesNo', 'Question')
    if ($ok -ne 'Yes') { return }
    Invoke-ControlChange {
        param($c)
        $c.whitelist = @($c.whitelist | Where-Object { -not ($sel -contains ($(if ($_ -is [System.Collections.IDictionary]) { [string]$_.ip } else { [string]$_ }))) })
    }.GetNewClosure() "$env:COMPUTERNAME`: убрано из исключений $($sel -join ', ')"
})

# ---------------- таймеры ----------------
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 30000
$timer.add_Tick({ Import-View })
$timerFast = New-Object System.Windows.Forms.Timer; $timerFast.Interval = 5000
$script:fastTicks = 0
$timerFast.add_Tick({ $script:fastTicks++; Import-View; if ($script:fastTicks -ge 12) { $timerFast.Stop(); $script:fastTicks = 0 } })

$form.add_Shown({ Import-View; $timer.Start() })
[void]$form.ShowDialog()
