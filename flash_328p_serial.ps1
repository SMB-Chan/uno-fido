# Flash ATmega328P via Serial (When 16U2 is in USB-Serial mode)
param(
    [string]$Port = ""
)

if (-not $Port) {
    $ports = Get-CimInstance -ClassName Win32_SerialPort | Where-Object { $_.Description -match "Arduino" -or $_.Name -match "COM" }
    if ($ports) {
        $Port = ($ports | Select-Object -First 1).DeviceID
        Write-Host "Auto-detected port: $Port"
    } else {
        $Port = Read-Host "Please enter Arduino COM port (e.g. COM3)"
    }
}

if (-not $Port) {
    Write-Error "No COM port specified."
    exit 1
}

# Paths are relative to this script so the repository works from any checkout.
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$sketch = Join-Path $repo 'fido_uno_key'
$build = Join-Path $sketch 'build'
$hex = Join-Path $build 'fido_uno_key.ino.hex'

$cli = (Get-Command arduino-cli -ErrorAction SilentlyContinue).Source
if (-not $cli) {
    foreach ($p in @("C:\Program Files\Arduino CLI\arduino-cli.exe", "$env:LOCALAPPDATA\arduino-cli\arduino-cli.exe")) {
        if (Test-Path $p) { $cli = $p; break }
    }
}
if (-not $cli) { throw "arduino-cli not found (winget install ArduinoSA.CLI)" }

if (-not (Test-Path $hex)) {
    Write-Host "Building sketch first..."
    & $cli compile --fqbn arduino:avr:uno --build-path $build $sketch
    if ($LASTEXITCODE -ne 0) { throw "compile failed" }
}

Write-Host "Flashing ATmega328P on $Port..."
& $cli upload -p $Port --fqbn arduino:avr:uno --input-dir $build
if ($LASTEXITCODE -eq 0) {
    Write-Host "Flashing successful!" -ForegroundColor Green
} else {
    Write-Host "Flashing failed. Exit code: $LASTEXITCODE" -ForegroundColor Red
}
