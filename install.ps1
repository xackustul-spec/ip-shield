# IP Shield bootstrap. Usage (PowerShell as Administrator):
#   [Net.ServicePointManager]::SecurityProtocol=3072; $IPShieldToken='github_pat_...'; irm https://raw.githubusercontent.com/xackustul-spec/ip-shield/main/install.ps1 | iex
# Re-run without the token to update an installed computer.
& {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    $base = 'https://raw.githubusercontent.com/xackustul-spec/ip-shield/main'
    $tmp = Join-Path $env:TEMP 'ipshield-setup.ps1'
    $wc = New-Object Net.WebClient
    $wc.Encoding = [Text.Encoding]::UTF8
    $txt = $wc.DownloadString($base + '/setup.ps1?t=' + [DateTime]::UtcNow.Ticks)
    [IO.File]::WriteAllText($tmp, $txt.TrimStart([char]0xFEFF), (New-Object Text.UTF8Encoding($true)))
    $tok = ''
    $v = Get-Variable -Name IPShieldToken -Scope Global -ErrorAction SilentlyContinue
    if ($v -and $v.Value) { $tok = [string]$v.Value }
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $tmp -Token $tok
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name IPShieldToken -Scope Global -ErrorAction SilentlyContinue
}
