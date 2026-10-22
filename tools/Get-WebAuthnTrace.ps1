<#
.SYNOPSIS
  Windows Hello / セキュリティキーのセットアップが失敗する原因を切り分けるための診断スクリプト。

.DESCRIPTION
  「このセキュリティ キーは使用できません。別のセキュリティ キーを使用してください。」
  は Windows の WebAuthn スタックが出す汎用エラーで、CTAP2 のどの段階で失敗しても
  同じ文面になります。このスクリプトは 2 つのことを行います。

    1. 環境チェック (-Mode Env)
       - Windows のビルド（24H2 の既知不具合の判定を含む）
       - セキュリティキー用クレデンシャル プロバイダーが無効化されていないか
       - Windows Hello / NGC / 生体認証サービスが動いているか
       - VID 1209 / PID F1D0（このキー）が PnP で見えているか
       - パスキー関連のポリシー レジストリ

    2. CTAP トレース (-Mode Trace)
       Microsoft-Windows-WebAuthN/Operational のイベントから、
       Windows がキーに投げた CTAP2 コマンドと、キーが返したステータスを取り出す。
       どのコマンドがどの値で落ちたかが分かれば、ファーム側の問題か
       Windows 側（あるいは Microsoft アカウント側）の問題かを確定できる。

.PARAMETER Mode
  Env / Trace / Both（既定は Both）

.PARAMETER Seconds
  Trace モードで待つ秒数（既定 120）。この間に Windows Hello のセットアップを
  1 回だけ実行してください。

.PARAMETER Clear
  トレース開始前にログを消す（要 管理者）。前回の結果と混ざりません。

.PARAMETER EnableLog
  Operational ログが無効なら有効化する（要 管理者）。

.EXAMPLE
  # 管理者の PowerShell で
  powershell -ExecutionPolicy Bypass -File .\tools\Get-WebAuthnTrace.ps1 -Mode Both -Clear -EnableLog
#>
[CmdletBinding()]
param(
  [ValidateSet('Env', 'Trace', 'Both')]
  [string]$Mode = 'Both',
  [int]$Seconds = 120,
  [switch]$Clear,
  [switch]$EnableLog
)

$ErrorActionPreference = 'Continue'
$LogName = 'Microsoft-Windows-WebAuthN/Operational'

function Write-Head([string]$Text) {
  Write-Host ''
  Write-Host ('=' * 68) -ForegroundColor DarkCyan
  Write-Host " $Text" -ForegroundColor Cyan
  Write-Host ('=' * 68) -ForegroundColor DarkCyan
}

function Write-Ok([string]$Text)   { Write-Host "  [OK]   $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text) { Write-Host "  [注意] $Text" -ForegroundColor Yellow }
function Write-Ng([string]$Text)   { Write-Host "  [NG]   $Text" -ForegroundColor Red }
function Write-Info([string]$Text) { Write-Host "         $Text" -ForegroundColor Gray }

# ---------------------------------------------------------------- 定数テーブル
$CtapCmd = @{
  0x01 = 'authenticatorMakeCredential'
  0x02 = 'authenticatorGetAssertion'
  0x04 = 'authenticatorGetInfo'
  0x05 = 'authenticatorClientPIN(legacy)'
  0x06 = 'authenticatorClientPIN'
  0x07 = 'authenticatorReset'
  0x08 = 'authenticatorGetNextAssertion'
  0x09 = 'authenticatorBioEnrollment'
  0x0A = 'authenticatorCredentialManagement'
  0x0B = 'authenticatorSelection'
  0x0C = 'authenticatorLargeBlobs'
  0x0D = 'authenticatorConfig'
}

$CtapStatus = @{
  0x00 = 'CTAP2_OK'
  0x01 = 'CTAP1_ERR_INVALID_COMMAND'
  0x02 = 'CTAP1_ERR_INVALID_PARAMETER'
  0x03 = 'CTAP1_ERR_INVALID_LENGTH'
  0x04 = 'CTAP1_ERR_INVALID_SEQ'
  0x05 = 'CTAP1_ERR_TIMEOUT'
  0x06 = 'CTAP1_ERR_CHANNEL_BUSY'
  0x0A = 'CTAP1_ERR_OTHER'
  0x11 = 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE'
  0x12 = 'CTAP2_ERR_INVALID_CBOR'
  0x14 = 'CTAP2_ERR_MISSING_PARAMETER'
  0x15 = 'CTAP2_ERR_LIMIT_EXCEEDED'
  0x16 = 'CTAP2_ERR_FP_DATABASE_FULL'
  0x19 = 'CTAP2_ERR_CREDENTIAL_EXCLUDED'
  0x21 = 'CTAP2_ERR_PROCESSING'
  0x22 = 'CTAP2_ERR_INVALID_CREDENTIAL'
  0x23 = 'CTAP2_ERR_USER_ACTION_PENDING'
  0x24 = 'CTAP2_ERR_OPERATION_PENDING'
  0x25 = 'CTAP2_ERR_NO_OPERATIONS'
  0x26 = 'CTAP2_ERR_UNSUPPORTED_ALGORITHM'
  0x27 = 'CTAP2_ERR_OPERATION_DENIED'
  0x28 = 'CTAP2_ERR_KEY_STORE_FULL'
  0x2A = 'CTAP2_ERR_UNSUPPORTED_OPTION'
  0x2B = 'CTAP2_ERR_INVALID_OPTION'
  0x2C = 'CTAP2_ERR_KEEPALIVE_CANCEL'
  0x2D = 'CTAP2_ERR_NO_CREDENTIALS'
  0x2E = 'CTAP2_ERR_USER_ACTION_TIMEOUT'
  0x2F = 'CTAP2_ERR_NOT_ALLOWED'
  0x31 = 'CTAP2_ERR_PIN_INVALID'
  0x32 = 'CTAP2_ERR_PIN_BLOCKED'
  0x33 = 'CTAP2_ERR_PIN_AUTH_INVALID'
  0x34 = 'CTAP2_ERR_PIN_AUTH_BLOCKED'
  0x35 = 'CTAP2_ERR_PIN_NOT_SET'
  0x36 = 'CTAP2_ERR_PIN_REQUIRED'
  0x37 = 'CTAP2_ERR_PIN_POLICY_VIOLATION'
  0x38 = 'CTAP2_ERR_PIN_TOKEN_TIMEOUT'
  0x39 = 'CTAP2_ERR_REQUEST_TOO_LARGE'
  0x3A = 'CTAP2_ERR_ACTION_TIMEOUT'
  0x3B = 'CTAP2_ERR_UP_REQUIRED'
  0x3C = 'CTAP2_ERR_UV_BLOCKED'
  0x3D = 'CTAP2_ERR_INTEGRITY_FAILURE'
  0x3E = 'CTAP2_ERR_INVALID_SUBCOMMAND'
  0x3F = 'CTAP2_ERR_UV_INVALID'
  0x40 = 'CTAP2_ERR_UNAUTHORIZED_PERMISSION'
  0x7F = 'CTAP1_ERR_OTHER / CTAP2_ERR_OTHER (ファーム独自)'
}

# HID レベルのコマンド（イベントに HID パケットが入っている場合の表示用）
$HidCmd = @{
  0x01 = 'PING'; 0x02 = 'MSG'; 0x03 = 'LOCK'; 0x04 = 'INIT'
  0x05 = 'WINK'; 0x06 = 'CBOR'; 0x07 = 'CANCEL'; 0x08 = 'KEEPALIVE'
  0x09 = 'ERROR'
}

# ---------------------------------------------------------------- ユーティリティ
function Get-HexDump([byte[]]$Bytes, [int]$Max = 96) {
  if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '(空)' }
  $n = [Math]::Min($Bytes.Length, $Max)
  $sb = New-Object System.Text.StringBuilder
  for ($i = 0; $i -lt $n; $i++) {
    if ($i -gt 0 -and ($i % 16) -eq 0) { [void]$sb.Append(' ') }
    [void]$sb.Append($Bytes[$i].ToString('X2'))
    [void]$sb.Append(' ')
  }
  $hex = $sb.ToString().Trim()
  if ($Bytes.Length -gt $Max) { $hex += (" ...(全 {0} バイト)" -f $Bytes.Length) }
  return $hex
}

function Get-AsciiRuns([byte[]]$Bytes) {
  # GetInfo のバージョン文字列や拡張名は CBOR のテキスト文字列として入っている。
  # 4 文字以上の印字可能 ASCII の連続を拾えば、内容がそのまま読める。
  if ($null -eq $Bytes) { return @() }
  $runs = New-Object System.Collections.Generic.List[string]
  $cur = New-Object System.Text.StringBuilder
  foreach ($b in $Bytes) {
    if ($b -ge 0x20 -and $b -le 0x7E) {
      [void]$cur.Append([char]$b)
    } else {
      if ($cur.Length -ge 4) { $runs.Add($cur.ToString()) }
      [void]$cur.Clear()
    }
  }
  if ($cur.Length -ge 4) { $runs.Add($cur.ToString()) }
  return $runs
}

function Get-PropValue($Event, [string[]]$Names) {
  foreach ($n in $Names) {
    foreach ($p in $Event.Properties) {
      if ($p.Name -eq $n -and $null -ne $p.Value) { return $p.Value }
    }
  }
  return $null
}

# ---------------------------------------------------------------- 環境チェック
function Show-Environment {
  Write-Head '1. 環境チェック'

  # --- Windows のビルド
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = 0
    if ($cv.PSObject.Properties.Name -contains 'UBR') { $ubr = [int]$cv.UBR }
    $build = ''
    if ($cv.PSObject.Properties.Name -contains 'CurrentBuildNumber') { $build = [string]$cv.CurrentBuildNumber }
    $disp = ''
    if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $disp = [string]$cv.DisplayVersion }
    $full = "$build.$ubr"
    Write-Ok ("Windows {0} (build {1}, {2})" -f $os.Caption, $full, $disp)

    if ($build -eq '26100' -and $ubr -lt 6584) {
      Write-Warn2 'Windows 11 24H2 の既知不具合（build 26100.6584 = KB5065426 で修正）'
      Write-Info 'この範囲のビルドでは、設定 > アカウント > サインイン オプション > セキュリティ キー > 管理 で'
      Write-Info 'PIN の変更やキーの管理が失敗します（YubiKey でも発生）。Windows Update を適用してください。'
    }
  } catch {
    Write-Warn2 "ビルド情報を取得できません: $($_.Exception.Message)"
  }

  # --- セキュリティキー用クレデンシャル プロバイダー
  $fidoClsid = '{F8A1793B-7873-4046-B2A7-1F318747F427}'
  try {
    $base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$fidoClsid"
    if (Test-Path $base) {
      $p = Get-ItemProperty $base
      $disabled = $false
      if ($p.PSObject.Properties.Name -contains 'Disabled') { $disabled = ($p.Disabled -ne 0) }
      if ($disabled) {
        Write-Ng 'FIDO セキュリティキーのクレデンシャル プロバイダーが無効化されています（Disabled=1）'
        Write-Info 'この状態では、キーが正常でも Windows のダイアログが「使用できません」で止まります。'
      } else {
        Write-Ok 'FIDO セキュリティキーのクレデンシャル プロバイダーは有効'
      }
    } else {
      Write-Warn2 'FIDO クレデンシャル プロバイダーのキーがありません（Windows の版によっては正常）'
    }
  } catch {
    Write-Warn2 "クレデンシャル プロバイダーを確認できません: $($_.Exception.Message)"
  }

  # --- サードパーティ製のプロバイダー（Duo / Kensington 等が Hello を壊すことがある）
  try {
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
    $third = Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
      $v = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
      if ($v) { $v }
    } | Where-Object { $_ -match 'Duo|Kensington|VeriMark|Yubico|Feitian|HID|Secu|Bio' }
    if ($third) {
      Write-Warn2 'サードパーティ製の認証プロバイダーが登録されています（干渉することがあります）'
      $third | Select-Object -Unique | ForEach-Object { Write-Info $_ }
    } else {
      Write-Ok '干渉しそうなサードパーティ製プロバイダーは見つかりません'
    }
  } catch { }

  # --- サービス
  foreach ($svc in @('NgcSvc', 'NgcCtnrSvc', 'WbioSrvc', 'CryptSvc')) {
    try {
      $s = Get-Service -Name $svc -ErrorAction Stop
      if ($s.Status -eq 'Running') { Write-Ok "$svc : $($s.Status)" }
      else { Write-Warn2 "$svc : $($s.Status)（手動でも可。止まっていると Hello が失敗することがあります）" }
    } catch {
      Write-Info "$svc : この環境には存在しません"
    }
  }

  # --- このキーが見えているか（VID 1209 / PID F1D0）
  try {
    $dev = Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
      $_.InstanceId -match 'VID_1209&PID_F1D0'
    }
    if ($dev) {
      foreach ($d in $dev) {
        if ($d.Status -eq 'OK') { Write-Ok "キーを検出: $($d.FriendlyName) [$($d.Status)]" }
        else { Write-Ng "キーは見えるが状態が異常: $($d.FriendlyName) [$($d.Status)]" }
      }
    } else {
      Write-Ng 'VID_1209&PID_F1D0 の HID デバイスが見つかりません（16U2 の書き換え／USB 接続を確認）'
    }
  } catch {
    Write-Warn2 "PnP 情報を取得できません: $($_.Exception.Message)"
  }

  # --- パスキー / セキュリティキー関連ポリシー
  try {
    $pw = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\SecurityKey'
    if (Test-Path $pw) {
      $v = Get-ItemProperty $pw
      if ($v.PSObject.Properties.Name -contains 'UseSecurityKeyForSignin') {
        Write-Info "UseSecurityKeyForSignin = $($v.UseSecurityKeyForSignin)（0: 無効 / 1: 有効 / 2: 強制）"
      }
    }
    $dis = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
    if (Test-Path $dis) {
      $v2 = Get-ItemProperty $dis
      if ($v2.PSObject.Properties.Name -contains 'DisablePostLogonProvisioning') {
        Write-Info "DisablePostLogonProvisioning = $($v2.DisablePostLogonProvisioning)"
      }
    }
    Write-Info 'パスキー全般の許可: 設定 > プライバシーとセキュリティ > パスキー（Passkey access）を必ず確認'
    Write-Info 'ここがオフだと、YubiKey でも Windows セキュリティのダイアログ自体が出ません。'
  } catch { }
}

# ---------------------------------------------------------------- トレース
function Show-Trace {
  Write-Head '2. CTAP トレース'

  $existing = $null
  try { $existing = Get-WinEvent -ListLog $LogName -ErrorAction Stop } catch {
    Write-Ng "$LogName が存在しません（Windows 10 の一部の版）。この場合はイベントでの切り分けはできません。"
    return
  }

  if (-not $existing.IsEnabled) {
    if ($EnableLog) {
      try {
        & wevtutil.exe sl $LogName /e:true | Out-Null
        Write-Ok 'Operational ログを有効化しました'
      } catch {
        Write-Ng "ログを有効化できません（管理者で実行してください）: $($_.Exception.Message)"
      }
    } else {
      Write-Warn2 'Operational ログが無効です。-EnableLog を付けて管理者で実行してください'
    }
  }

  if ($Clear) {
    try {
      & wevtutil.exe cl $LogName | Out-Null
      Write-Ok 'ログを消去しました'
    } catch {
      Write-Warn2 "ログを消去できません（管理者で実行してください）: $($_.Exception.Message)"
    }
  }

  Write-Host ''
  Write-Host "  これから $Seconds 秒待ちます。" -ForegroundColor Yellow
  Write-Host '  その間に「設定 > アカウント > サインイン オプション > セキュリティ キー」で' -ForegroundColor Yellow
  Write-Host '  エラーを 1 回だけ再現してください（複数回やるとログが混ざります）。' -ForegroundColor Yellow
  Write-Host ''

  $start = Get-Date
  $end = $start.AddSeconds($Seconds)
  $seen = New-Object System.Collections.Generic.HashSet[long]

  while ((Get-Date) -lt $end) {
    $events = @()
    try {
      $events = Get-WinEvent -FilterHashtable @{
        LogName   = $LogName
        StartTime = $start
      } -ErrorAction SilentlyContinue
    } catch { }

    foreach ($e in ($events | Sort-Object RecordId)) {
      if ($seen.Contains([long]$e.RecordId)) { continue }
      [void]$seen.Add([long]$e.RecordId)

      $t = $e.TimeCreated.ToString('HH:mm:ss.fff')
      Write-Host ''
      Write-Host ("  [{0}] EventID={1}  {2}" -f $t, $e.Id, $e.ProviderName) -ForegroundColor Magenta

      # メッセージ（1 行に丸める）
      $msg = ''
      try { $msg = ($e.Message -replace '\s+', ' ').Trim() } catch { }
      if ($msg) {
        if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + '...' }
        Write-Host "      $msg" -ForegroundColor DarkGray
      }

      # CBOR / HID のバイト列を拾う
      $reqBytes = $null
      $resBytes = $null
      foreach ($p in $e.Properties) {
        $val = $p.Value
        if ($val -is [byte[]] -and $val.Length -gt 0) {
          $name = [string]$p.Name
          if ($name -match 'Request|req|Cmd|Data') { if (-not $reqBytes) { $reqBytes = $val } }
          elseif ($name -match 'Response|resp|Result') { if (-not $resBytes) { $resBytes = $val } }
        }
      }
      # プロパティ名が違う版もあるので、2 つのバイト列を順に Request/Response とみなす
      if (-not $reqBytes -or -not $resBytes) {
        $byteProps = @($e.Properties | Where-Object { $_.Value -is [byte[]] -and $_.Value.Length -gt 0 })
        if ($byteProps.Count -ge 1 -and -not $reqBytes) { $reqBytes = $byteProps[0].Value }
        if ($byteProps.Count -ge 2 -and -not $resBytes) { $resBytes = $byteProps[1].Value }
      }

      if ($reqBytes) {
        $cmdName = 'CTAPHID?'
        $first = $reqBytes[0]
        if ($CtapCmd.ContainsKey([int]$first)) { $cmdName = $CtapCmd[[int]$first] }
        Write-Host ("      REQ  {0,-2} {1}" -f ('0x{0:X2}' -f $first), $cmdName) -ForegroundColor Cyan
        Write-Host ("           {0}" -f (Get-HexDump $reqBytes))
        $strings = Get-AsciiRuns $reqBytes
        if ($strings.Count -gt 0) {
          Write-Host ("           文字列: {0}" -f (($strings | Select-Object -First 12) -join ' | ')) -ForegroundColor DarkGray
        }
      }
      if ($resBytes) {
        $stName = '不明'
        $first = $resBytes[0]
        if ($CtapStatus.ContainsKey([int]$first)) { $stName = $CtapStatus[[int]$first] }
        $color = 'Green'
        if ($first -ne 0) { $color = 'Red' }
        Write-Host ("      RES  {0,-2} {1}" -f ('0x{0:X2}' -f $first), $stName) -ForegroundColor $color
        Write-Host ("           {0}" -f (Get-HexDump $resBytes))
        $strings = Get-AsciiRuns $resBytes
        if ($strings.Count -gt 0) {
          Write-Host ("           文字列: {0}" -f (($strings | Select-Object -First 12) -join ' | ')) -ForegroundColor DarkGray
        }
      }
    }
    Start-Sleep -Milliseconds 700
  }

  Write-Host ''
  Write-Head '3. 読み方（この表で原因が決まります）'
  Write-Info 'RES の値ごとの意味:'
  Write-Info '  0x00 ................................................ そのコマンドは成功'
  Write-Info '  0x2A (UNSUPPORTED_OPTION) が 0x08 / 0x0A に対して出た ... ファーム未実装（getNextAssertion / credMgmt）'
  Write-Info '  0x28 (KEY_STORE_FULL) .............................. スロット 5 個が埋まっている → 鍵リセット'
  Write-Info '  0x19 (CREDENTIAL_EXCLUDED) ......................... 同じ RP の資格情報が既にある → 鍵リセット'
  Write-Info '  0x36 / 0x35 ........................................ PIN 要求の不整合'
  Write-Info '  0x33 (PIN_AUTH_INVALID) ............................ PIN トークン検証か RP バインドで失敗 → ファーム要修正'
  Write-Info '  0x39 (REQUEST_TOO_LARGE) ........................... 512 バイト超（Windows Hello の makeCredential が長い）'
  Write-Info '  0x7F ............................................... ファーム内部エラー'
  Write-Info ''
  Write-Info 'REQ が 0x04 (GetInfo) の応答で止まっている ..... Windows 側の問題（プロバイダー無効・パスキー許可オフ）'
  Write-Info 'REQ が 0x01 まで来ている ....................... キーは使われている。RES を見て判断'
  Write-Info 'イベントが 1 件も出ない ........................ Windows のダイアログがキーに到達していない'
}

# ---------------------------------------------------------------- 実行
Write-Host ''
Write-Host ' uno-fido / Windows Hello セキュリティキー診断' -ForegroundColor White
Write-Host ' （このスクリプトは読み取りのみ。レジストリやキーは変更しません）' -ForegroundColor DarkGray

if ($Mode -eq 'Env' -or $Mode -eq 'Both') { Show-Environment }
if ($Mode -eq 'Trace' -or $Mode -eq 'Both') { Show-Trace }

Write-Host ''
