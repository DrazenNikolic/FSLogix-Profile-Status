<#
  FSLogix-Status_v1.0.ps1
  One script, two modes:
    -CurrentUser (default)  → show only current user's FSLogix status
    -AllUsers               → show all sessions (admin may be required)
  UI: gray borders; blue attribution under title; spacer line; legend on its own line.
  Colored status dot (●) per row; only "Success" text is green.
#>
[CmdletBinding(DefaultParameterSetName='Current')]
param(
  [Parameter(ParameterSetName='Current')][switch]$CurrentUser = $true,
  [Parameter(ParameterSetName='All')][switch]$AllUsers,
  [int]$Watch = 0,
  [switch]$IncludeEvents,
  [int]$EventCount = 3,
  [switch]$NoColor,
  [switch]$Ascii,
  [switch]$BeepOnError,
  [switch]$ShowConfig,
  [switch]$CheckShares,
  [int]$TailLogs = 0,
  [string]$ExportCsv,
  [string]$ExportJson,
  [switch]$Copy
)

$ErrorActionPreference = 'Stop'

# ---------- ANSI helpers ----------
$esc   = [char]27
$reset = "$esc[0m"
$AnsiEnabled = $true
try {
  if ($NoColor) { $AnsiEnabled = $false }
  elseif ($PSStyle -and $PSStyle.Foreground) { $AnsiEnabled = $true }
  elseif ($env:WT_SESSION) { $AnsiEnabled = $true }
  else { $AnsiEnabled = $Host.UI.SupportsVirtualTerminal }
} catch { $AnsiEnabled = $false }

function AnsiRgb([string]$hex,[switch]$bg){
  if(-not $AnsiEnabled){ return '' }
  $hex=$hex.TrimStart('#'); if($hex.Length -lt 6){ return '' }
  $r=[Convert]::ToInt32($hex.Substring(0,2),16)
  $g=[Convert]::ToInt32($hex.Substring(2,2),16)
  $b=[Convert]::ToInt32($hex.Substring(4,2),16)
  if($bg){ return "$esc[48;2;${r};${g};${b}m" } else { return "$esc[38;2;${r};${g};${b}m" }
}

# ---------- Colors (gray UI; only Success text colored) ----------
$fgGreen = AnsiRgb '#00C853'
$fgYellow= AnsiRgb '#FFD600'
$fgRed   = AnsiRgb '#D50000'
$fgGray  = AnsiRgb '#94A3B8'
$fgBlue  = AnsiRgb '#3B82F6'

# ---------- Box characters ----------
$B = if($Ascii){ @{ tl='+'; tr='+'; bl='+'; br='+'; h='-'; v='|'; j1='+'; j2='+' } }
     else       { @{ tl='┌'; tr='┐'; bl='└'; br='┘'; h='─'; v='│'; j1='├'; j2='┤' } }

# ---------- FSLogix registry roots ----------
$sessionRoot = 'HKLM:\SOFTWARE\FSLogix\Profiles\Sessions'
$profilesRoot= 'HKLM:\SOFTWARE\FSLogix\Profiles'

# ---------- Mappings ----------
$mapStatus = @{ 0='Success'; 100='Waiting'; 200='InProgress'; 300='AlreadyAttached' }
$mapReason = @{ 0='Attached';1='NotInIncludeGroup';2='InExcludeGroup';3='LocalProfileExists';4='ShortSid';5='Unset';6='ComponentNotEnabled';7='WindowsTempProfile';8='NotAVDSession';9='LoadFailed' }
$advice    = @{
  0='Attached: profile/container mounted successfully.'
  1='User not in include group: check include policy and group membership.'
  2='User in exclude group: verify exclusion policy or group membership.'
  3='Local profile exists: consider deleting/renaming stale local profile or enable DeleteLocalProfileWhenVHDShouldApply.'
  6='Component disabled: check FSLogix Profiles "Enabled" policy/registry.'
  7='Temp profile in use: check logs for prior error and disk locks.'
  8='Not an AVD session: ensure targeting logic is correct.'
  9='Load failed: check for lock/in-use, permissions, or connectivity.'
}

# ---------- Utils ----------
function Strip-ANSI([string]$s){ if(-not $s){ return '' } ($s -replace "\e\[[\d;]*m","") }
function CleanLen([string]$s){ (Strip-ANSI $s).Length }
function SidToName([string]$sid){ try { ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { $sid } }

# ---------- Table widths ----------
$wIcon=1; $wA=28; $wSt=6; $wSTxt=16; $wRe=6; $wRTxt=22; $wErr=12
$fmt = "│ {0} │ {1,-$wA} │ {2,$wSt} │ {3,-$wSTxt} │ {4,$wRe} │ {5,-$wRTxt} │ {6,-$wErr} │"

function Draw-Header([int]$lineLen, [string]$modeText){
  $inner=$lineLen-2
  $top=$B.tl+($B.h*$inner)+$B.tr
  $bot=$B.bl+($B.h*$inner)+$B.br
  Write-Host ($fgGray+$top+$reset)

  $title    = " FSLogix Profile Status ($modeText) "
  $attribP  = ' Created by Drazen Nikolic — LinkedIn: https://www.linkedin.com/in/drazen-nikolic-816906142/ '
  $attribC  = $fgBlue + $attribP + $reset
  $legendP  = '  Legend:  ● Healthy  ● Warning  ● Error'
  $legendC  = '  Legend:  ' + $fgGreen+'●'+$reset+' Healthy  ' + $fgYellow+'●'+$reset+' Warning  ' + $fgRed+'●'+$reset+' Error'

  $lines = @(
    @{text=$title;   plain=$title},
    @{text=$attribC; plain=$attribP},
    @{text='';       plain=''},       # spacer line
    @{text=$legendC; plain=$legendP}
  )

  foreach($l in $lines){
    $pad = ' ' * [Math]::Max(0, $inner - (CleanLen $l.plain))
    Write-Host ($fgGray + $B.v + $reset + $l.text + $pad + $fgGray + $B.v + $reset)
  }
  Write-Host ($fgGray+$bot+$reset)
}

# ---------- Row helpers ----------
function New-RowFromProps([string]$sid, $p){
  $acct = SidToName $sid
  $hasS = $p.PSObject.Properties.Match('Status').Count -gt 0
  $hasR = $p.PSObject.Properties.Match('Reason').Count -gt 0
  $hasE = $p.PSObject.Properties.Match('Error').Count  -gt 0
  $hasL = $p.PSObject.Properties.Match('LastError').Count -gt 0

  $status = if($hasS){ [int]$p.Status } else { -1 }
  $reason = if($hasR){ [int]$p.Reason } else { -1 }
  $errVal = if($hasE){ [uint32]$p.Error } elseif($hasL){ [uint32]$p.LastError } else { 0 }

  $statusText = if($mapStatus.ContainsKey($status)){ $mapStatus[$status] } elseif($status -ge 0){ "Code $status" } else { 'Unknown' }
  $reasonText = if($mapReason.ContainsKey($reason)){ $mapReason[$reason] } elseif($reason -ge 0){ "Code $reason" } else { '' }

  $sev='Green'
  if (($status -ne 0 -and $status -ne -1) -or $reason -in 7,9) { $sev='Red' }
  elseif ($status -in 100,200,300 -or $reason -in 1,2,3,4,5,8 -or ($status -eq -1 -and $reason -eq -1)) { $sev='Yellow' }

  [pscustomobject]@{
    Account    = $acct
    SID        = $sid
    Status     = if($status -ge 0){ $status } else { $null }
    StatusText = $statusText
    Reason     = if($reason -ge 0){ $reason } else { $null }
    ReasonText = $reasonText
    ErrorHex   = ('0x{0:X8}' -f $errVal)
    Severity   = $sev
  }
}

# ---------- Data fetchers ----------
function Get-CurrentUserRow {
  if (-not (Test-Path $sessionRoot)) { return $null }
  $sid  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $k    = Join-Path $sessionRoot $sid
  if (-not (Test-Path $k)) { return $null }
  try {
    $p = Get-ItemProperty $k -ErrorAction Stop
    return New-RowFromProps -sid $sid -p $p
  } catch { return $null }
}

function Get-FSLogixSessions {
  $rows = @()
  if (Test-Path $sessionRoot) {
    try {
      $keys = Get-ChildItem $sessionRoot -ErrorAction Stop
      foreach($k in $keys){
        try { $p = Get-ItemProperty $k.PSPath; $rows += New-RowFromProps -sid $k.PSChildName -p $p } catch {}
      }
    } catch {}
  }
  if(-not $rows -or $rows.Count -eq 0){
    # Fallback: ProfileList + current user → probe per SID
    $cand = @()
    try { $cand += (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName) } catch {}
    try { $cand += [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch {}
    $cand = $cand | Sort-Object -Unique | Where-Object { $_ -match '^S-1-5-21-' }
    foreach($sid in $cand){
      $path = Join-Path $sessionRoot $sid
      if(Test-Path $path){ try{ $rows += New-RowFromProps -sid $sid -p (Get-ItemProperty $path) }catch{} }
    }
  }
  $rows | Sort-Object @{Expression={ switch($_.Severity){ 'Red' {0}; 'Yellow'{1}; default{2} } }}, @{Expression='Account';Ascending=$true}
}

# ---------- Table renderers ----------
function Draw-TableCurrent([pscustomobject]$r){
  $hdr = ($fmt -f '#','Account','St','StatusText','Re','ReasonText','Error')
  $len = CleanLen $hdr
  $top =  $B.tl + ($B.h * ($len-2)) + $B.tr
  $mid =  $B.j1 + ($B.h * ($len-2)) + $B.j2
  $bot =  $B.bl + ($B.h * ($len-2)) + $B.br

  Draw-Header -lineLen $len -modeText 'Current User'
  Write-Host ($fgGray + $top + $reset)
  Write-Host ($fgGray + $hdr + $reset)
  Write-Host ($fgGray + $mid + $reset)

  $icon = switch ($r.Severity) { 'Green' { $fgGreen + '●' + $reset } 'Yellow' { $fgYellow + '●' + $reset } default { $fgRed + '●' + $reset } }
  $acct = [string]$r.Account; if($acct.Length -gt $wA){ $acct = $acct.Substring(0,$wA) }
  $st   = if($r.Status -ne $null){ [string]$r.Status } else { '' }
  $rt   = if($r.Reason -ne $null){ [string]$r.Reason } else { '' }
  $stx  = [string]$r.StatusText; if($stx.Length -gt $wSTxt){ $stx=$stx.Substring(0,$wSTxt) }
  $rtx  = [string]$r.ReasonText; if($rtx.Length -gt $wRTxt){ $rtx=$rtx.Substring(0,$wRTxt) }
  if($r.Severity -eq 'Green'){ $stx = $fgGreen + $stx + $reset; $rtx = $fgGreen + $rtx + $reset }
  $err  = [string]$r.ErrorHex;   if($err.Length -gt $wErr){ $err=$err.Substring(0,$wErr) }

  Write-Host ($fmt -f $icon, $acct, $st, $stx, $rt, $rtx, $err)
  Write-Host ($fgGray + $bot + $reset)
  Write-Host ($fgGray + 'Note: Green = profile/container attached; Yellow = initializing/policy/group; Red = temp profile / load failure.' + $reset)
  Write-Host ($fgGray + 'Logs: C:\ProgramData\FSLogix\Logs\Profile' + $reset)
}

function Draw-TableAll([array]$rows){
  $hdr = ($fmt -f '#','Account','St','StatusText','Re','ReasonText','Error')
  $len = CleanLen $hdr
  $top =  $B.tl + ($B.h * ($len-2)) + $B.tr
  $mid =  $B.j1 + ($B.h * ($len-2)) + $B.j2
  $bot =  $B.bl + ($B.h * ($len-2)) + $B.br

  Draw-Header -lineLen $len -modeText 'All Users'
  Write-Host ($fgGray + $top + $reset)
  Write-Host ($fgGray + $hdr + $reset)
  Write-Host ($fgGray + $mid + $reset)

  foreach($r in $rows){
    $icon = switch ($r.Severity) { 'Green' { $fgGreen + '●' + $reset } 'Yellow' { $fgYellow + '●' + $reset } default { $fgRed + '●' + $reset } }
    $acct = [string]$r.Account; if($acct.Length -gt $wA){ $acct = $acct.Substring(0,$wA) }
    $st   = if($r.Status -ne $null){ [string]$r.Status } else { '' }
    $rt   = if($r.Reason -ne $null){ [string]$r.Reason } else { '' }
    $stx  = [string]$r.StatusText; if($stx.Length -gt $wSTxt){ $stx=$stx.Substring(0,$wSTxt) }
    $rtx  = [string]$r.ReasonText; if($rtx.Length -gt $wRTxt){ $rtx=$rtx.Substring(0,$wRTxt) }
    if($r.Severity -eq 'Green'){ $stx = $fgGreen + $stx + $reset; $rtx = $fgGreen + $rtx + $reset }
    $err  = [string]$r.ErrorHex;   if($err.Length -gt $wErr){ $err=$err.Substring(0,$wErr) }
    Write-Host ($fmt -f $icon, $acct, $st, $stx, $rt, $rtx, $err)
  }
  Write-Host ($fgGray + $bot + $reset)
  Write-Host ($fgGray + 'Note: Green = profile/container attached; Yellow = initializing/policy/group; Red = temp profile / load failure.' + $reset)
  Write-Host ($fgGray + 'Logs: C:\ProgramData\FSLogix\Logs\Profile' + $reset)
}

# ---------- Extra views ----------
function Show-EventsFor([string]$sid){
  Write-Host ''
  Write-Host ($fgGray + ("Recent FSLogix events (Operational) for SID {0}:" -f $sid) + $reset)  # v3.1 fix
  try {
    Get-WinEvent -LogName 'Microsoft-FSLogix-Apps/Operational' -MaxEvents 400 |
      Where-Object { $_.Message -match [Regex]::Escape($sid) } |
      Select-Object -First $EventCount TimeCreated, Id, LevelDisplayName, Message |
      Format-List
  } catch {}
}
function Show-Config {
  if (-not (Test-Path $profilesRoot)) { return }
  Write-Host ''
  Write-Host ($fgGray + 'FSLogix Profile configuration (machine scope):' + $reset)
  try {
    $cfg = Get-ItemProperty $profilesRoot -ErrorAction SilentlyContinue
    $enabled = if($cfg.Enabled -eq 1){ 'Enabled' } elseif($cfg.Enabled -eq 0){ 'Disabled' } else { 'Not set' }
    Write-Host ("  Enabled: {0}" -f $enabled)
    $locs = @(); try { $locs = Get-ItemPropertyValue -Path $profilesRoot -Name 'VHDLocations' -ErrorAction Stop } catch {}
    if($locs){ Write-Host "  VHDLocations:"; $locs | ForEach-Object { Write-Host "    - $_" } } else { Write-Host "  VHDLocations: (not set)" }
  } catch {}
}
function Check-Shares {
  try {
    $locs = Get-ItemPropertyValue -Path $profilesRoot -Name 'VHDLocations' -ErrorAction SilentlyContinue
    if(-not $locs){ return }
    Write-Host ''
    Write-Host ($fgGray + 'Connectivity check (VHDLocations):' + $reset)
    foreach($p in $locs){
      if($p -match '^(?:\\\\|//)'){
        $ok = Test-Path $p
        $mark = if($ok){ $fgGreen + 'OK' + $reset } else { $fgRed + 'FAIL' + $reset }
        Write-Host ("  {0}  {1}" -f $mark, $p)
      } else { Write-Host ("  (local path) {0}" -f $p) }
    }
  } catch {}
}
function Tail-Logs([int]$lines){
  if($lines -le 0){ return }
  $logDir = 'C:\ProgramData\FSLogix\Logs\Profile'
  if(-not (Test-Path $logDir)){ return }
  $file = Get-ChildItem $logDir -Filter 'Profile_*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if(-not $file){ return }
  Write-Host ''
  Write-Host ($fgGray + ("Tail of {0} (last {1} lines):" -f $file.FullName,$lines) + $reset)
  try {
    Get-Content -Tail $lines -Path $file.FullName | ForEach-Object {
      if($_ -match '(?i)error|failed'){ Write-Host ($fgRed + $_ + $reset) }
      elseif($_ -match '(?i)warn|warning'){ Write-Host ($fgYellow + $_ + $reset) }
      else { Write-Host $_ }
    }
  } catch {}
}
function Export-Data([array]$rows){
  if($ExportCsv){ try{ $rows | Export-Csv -Path $ExportCsv -NoTypeInformation -Force } catch {} }
  if($ExportJson){ try{ $rows | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding UTF8 -Force } catch {} }
  if($Copy){
    try {
      $one = ($rows | ForEach-Object { "{0}: St={1}({2}) Re={3}({4}) Err={5}" -f $_.Account,$_.Status,$_.StatusText,$_.Reason,$_.ReasonText,$_.ErrorHex }) -join " | "
      Set-Clipboard -Value $one
      Write-Host ($fgGray + 'Copied summary to clipboard.' + $reset)
    } catch {}
  }
}
function Show-Advice([array]$rows){
  $h=@()
  foreach($r in $rows){ if($advice.ContainsKey($r.Reason)){ $h += ("- {0}: {1}" -f $r.Account,$advice[$r.Reason]) } }
  if($h){ Write-Host ''; Write-Host ($fgGray + 'Hints:' + $reset); $h | ForEach-Object { Write-Host $_ } }
}

# ---------- Main ----------
function Render {
  Clear-Host
  if($AllUsers){
    $rows = Get-FSLogixSessions
    if(-not $rows -or $rows.Count -eq 0){
      Write-Host ($fgRed + 'No FSLogix session keys found or access denied under HKLM:\SOFTWARE\FSLogix\Profiles\Sessions.' + $reset)
      Write-Host ($fgGray + 'Tip: Run PowerShell as Administrator for full enumeration, or use -CurrentUser.' + $reset)
      return
    }
    Draw-TableAll -rows $rows
    Show-Advice $rows
    if($IncludeEvents){ foreach($r in $rows){ Show-EventsFor $r.SID } }
    if($ShowConfig){ Show-Config }
    if($CheckShares){ Check-Shares }
    if($TailLogs -gt 0){ Tail-Logs $TailLogs }
    Export-Data $rows
  }
  else {
    $row = Get-CurrentUserRow
    if($null -eq $row){
      Write-Host ($fgRed + 'Current user session key not found under HKLM:\SOFTWARE\FSLogix\Profiles\Sessions.' + $reset)
      return
    }
    Draw-TableCurrent -r $row
    if($advice.ContainsKey($row.Reason)){ Write-Host ''; Write-Host ($fgGray + 'Hint: ' + $advice[$row.Reason] + $reset) }
    if($IncludeEvents){ Show-EventsFor $row.SID }
    if($ShowConfig){ Show-Config }
    if($CheckShares){ Check-Shares }
    if($TailLogs -gt 0){ Tail-Logs $TailLogs }
    Export-Data @($row)
  }
}

Render
if ($Watch -gt 0) {
  Write-Host ''; Write-Host ($fgGray + "Watch mode active. Press 'q' to quit." + $reset)
  $stop=$false
  while(-not $stop){
    Start-Sleep -Seconds $Watch
    try { if ($Host.UI.RawUI.KeyAvailable) { $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp'); if ($k.Character -eq 'q') { $stop = $true; break } } } catch {}
    Render
  }
}
