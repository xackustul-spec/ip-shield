# IP Shield — общие функции агента и окна мониторинга
# Этот файл подключается из agent.ps1, ui.ps1 и setup.ps1 (dot-source).

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}

$Global:IPS_Version    = '1.0.0'
$Global:IPS_Root       = if ($env:IPSHIELD_ROOT) { $env:IPSHIELD_ROOT } else { Join-Path $env:ProgramData 'IPShield' }
$Global:IPS_ConfigPath = Join-Path $IPS_Root 'config.json'
$Global:IPS_StatePath  = Join-Path $IPS_Root 'state.json'
$Global:IPS_SharedPath = Join-Path $IPS_Root 'shared.json'
$Global:IPS_ViewPath   = Join-Path $IPS_Root 'view.json'
$Global:IPS_LogPath    = Join-Path $IPS_Root 'agent.log'
$Global:IPS_ForceFlag  = Join-Path $IPS_Root 'force-sync.flag'
$Global:IPS_Private    = @('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','100.64.0.0/10','0.0.0.0/8','224.0.0.0/3')

# ---------- журнал ----------
function Write-IPSLog([string]$Message) {
    $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $Message
    try {
        if ((Test-Path $IPS_LogPath) -and ((Get-Item $IPS_LogPath).Length -gt 2MB)) {
            Move-Item $IPS_LogPath "$IPS_LogPath.old" -Force
        }
        [IO.File]::AppendAllText($IPS_LogPath, $line + "`r`n", (New-Object Text.UTF8Encoding($true)))
    } catch {}
}

# ---------- JSON ----------
function ConvertTo-HT($obj) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        $h = @{}; foreach ($k in @($obj.Keys)) { $h[[string]$k] = ConvertTo-HT $obj[$k] }; return $h
    }
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}; foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-HT $p.Value }; return $h
    }
    if ($obj -is [datetime]) { return $obj.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if (($obj -is [System.Collections.IEnumerable]) -and ($obj -isnot [string])) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $obj) { [void]$list.Add((ConvertTo-HT $i)) }
        return ,$list.ToArray()
    }
    return $obj
}

function ConvertFrom-JsonHT([string]$Text) {
    if (-not $Text -or -not $Text.Trim()) { return $null }
    return ConvertTo-HT ($Text.TrimStart([char]0xFEFF) | ConvertFrom-Json)
}

function ConvertTo-JsonText($obj, [switch]$Pretty) {
    if ($Pretty) { return (ConvertTo-Json -InputObject $obj -Depth 12) }
    return (ConvertTo-Json -InputObject $obj -Depth 12 -Compress)
}

function Read-JsonFile([string]$Path, $Default) {
    if (-not (Test-Path $Path)) { return $Default }
    try {
        $r = ConvertFrom-JsonHT ([IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8))
        if ($null -eq $r) { return $Default }
        return $r
    } catch {
        Write-IPSLog "Ошибка чтения $Path : $($_.Exception.Message)"
        return $Default
    }
}

function Write-JsonFile([string]$Path, $Obj) {
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-JsonText $Obj), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $Path -Force
}

# ---------- время (строки UTC вида 2026-10-11T10:13:00Z сравниваются как текст) ----------
function Get-Stamp([datetime]$Date = (Get-Date)) { return $Date.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function ConvertFrom-Stamp($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}

# ---------- IP ----------
function Get-NormalIP([string]$Ip) {
    if (-not $Ip) { return $null }
    $Ip = $Ip.Trim()
    if ($Ip -like '::ffff:*') { $Ip = $Ip.Substring(7) }
    if ($Ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        foreach ($i in 1..4) { if ([int]$Matches[$i] -gt 255) { return $null } }
        return (($Ip.Split('.') | ForEach-Object { [int]$_ }) -join '.')
    }
    return $null
}

function Get-IPNum([string]$Ip) {
    $p = $Ip.Split('.')
    return ([int64]$p[0] * 16777216) + ([int64]$p[1] * 65536) + ([int64]$p[2] * 256) + [int64]$p[3]
}

function Test-IPEntry([string]$Entry) {
    if ($Entry -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        return ((Get-NormalIP $Matches[1]) -and ([int]$Matches[2] -le 32))
    }
    return [bool](Get-NormalIP $Entry)
}

function Test-IPInList([string]$Ip, $List) {
    if (-not $Ip -or -not $List) { return $false }
    $n = Get-IPNum $Ip
    foreach ($e in $List) {
        $s = if ($e -is [System.Collections.IDictionary]) { [string]$e['ip'] } else { [string]$e }
        if (-not $s) { continue }
        if ($s -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $baseIp = $Matches[1]; $bits = [int]$Matches[2]
            $size = [math]::Pow(2, 32 - $bits)
            if ([math]::Floor($n / $size) -eq [math]::Floor((Get-IPNum $baseIp) / $size)) { return $true }
        } elseif ($s.Trim() -eq $Ip) { return $true }
    }
    return $false
}

function Test-PrivateIP([string]$Ip) { return (Test-IPInList $Ip $IPS_Private) }

# ---------- настройки ----------
function Get-IPSConfig {
    $c = Read-JsonFile $IPS_ConfigPath $null
    if (-not $c) { return $null }
    $defaults = @{ owner='xackustul-spec'; codeRepo='ip-shield'; dataRepo='ip-shield-data'; branch='main';
                   threshold=5; windowDays=7; trustDays=30; syncMinutes=5; pushMinutes=10; keepDays=90;
                   lan=@('192.168.0.0/16') }
    foreach ($k in $defaults.Keys) { if ($null -eq $c[$k] -or "$($c[$k])" -eq '') { $c[$k] = $defaults[$k] } }
    return $c
}

# ---------- GitHub (приватный репозиторий с данными) ----------
function Get-HttpStatus($ErrorRecord) {
    try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { return 0 }
}

function Invoke-GH($Config, [string]$Method, [string]$Path, $Body) {
    $uri = "https://api.github.com/repos/$($Config.owner)/$($Config.dataRepo)/$Path"
    $headers = @{ Authorization = "Bearer $($Config.token)"; 'User-Agent' = 'IPShield'
                  Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
    $p = @{ Uri = $uri; Method = $Method; Headers = $headers; TimeoutSec = 40; UseBasicParsing = $true }
    if ($null -ne $Body) {
        $p.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonText $Body))
        $p.ContentType = 'application/json; charset=utf-8'
    }
    return Invoke-RestMethod @p
}

function Get-GHTree($Config) {
    $r = Invoke-GH $Config 'GET' "git/trees/$($Config.branch)?recursive=1" $null
    $map = @{}
    foreach ($t in $r.tree) { if ($t.type -eq 'blob') { $map[[string]$t.path] = [string]$t.sha } }
    return $map
}

function Get-GHBlobText($Config, [string]$Sha) {
    $r = Invoke-GH $Config 'GET' "git/blobs/$Sha" $null
    $bytes = [Convert]::FromBase64String(([string]$r.content -replace '\s', ''))
    return [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
}

function Get-GHFile($Config, [string]$Path) {
    try {
        $r = Invoke-GH $Config 'GET' "contents/$($Path)?ref=$($Config.branch)" $null
    } catch {
        if ((Get-HttpStatus $_) -eq 404) { return $null }
        throw
    }
    $bytes = [Convert]::FromBase64String(([string]$r.content -replace '\s', ''))
    return @{ text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF); sha = [string]$r.sha }
}

function Set-GHFile($Config, [string]$Path, [string]$Text, [string]$Sha, [string]$Message) {
    $body = @{ message = $Message; branch = $Config.branch
               content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text)) }
    if ($Sha) { $body.sha = $Sha }
    $r = Invoke-GH $Config 'PUT' "contents/$Path" $body
    return [string]$r.content.sha
}

# ---------- общий файл управления: исключения и разбаны ----------
function Initialize-Control($Ctl) {
    if (-not ($Ctl -is [System.Collections.IDictionary])) { $Ctl = @{} }
    if ($null -eq $Ctl['whitelist']) { $Ctl['whitelist'] = @() }
    $Ctl['whitelist'] = @($Ctl['whitelist'] | Where-Object { $_ })
    if (-not ($Ctl['unban'] -is [System.Collections.IDictionary])) { $Ctl['unban'] = @{} }
    return $Ctl
}

# $Mutator получает hashtable control и меняет его. Повторяет запись при конфликте.
function Update-Control($Config, [scriptblock]$Mutator, [string]$Message) {
    for ($i = 0; $i -lt 5; $i++) {
        $f = Get-GHFile $Config 'control.json'
        $ctl = Initialize-Control $(if ($f) { ConvertFrom-JsonHT $f.text } else { $null })
        & $Mutator $ctl
        $ctl['updated'] = Get-Stamp
        $sha = if ($f) { $f.sha } else { $null }
        try {
            [void](Set-GHFile $Config 'control.json' (ConvertTo-JsonText $ctl -Pretty) $sha $Message)
            return $ctl
        } catch {
            $s = Get-HttpStatus $_
            if ($s -eq 409 -or $s -eq 422) { Start-Sleep -Milliseconds (400 + (Get-Random -Maximum 1600)); continue }
            throw
        }
    }
    throw 'Не удалось записать control.json: файл одновременно меняют с другого компьютера, попробуйте ещё раз.'
}
