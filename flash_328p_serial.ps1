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

$hex = "d:\elegoo fide\fido_uno_key\build\fido_uno_key.ino.hex"
if (-not (Test-Path $hex)) {
    Write-Host "Building sketch first..."
    & "C:\Program Files\Arduino CLI\arduino-cli.exe" compile --fqbn arduino:avr:uno --build-path "d:\elegoo fide\fido_uno_key\build" "d:\elegoo fide\fido_uno_key"
}

Write-Host "Flashing ATmega328P on $Port..."
& "C:\Program Files\Arduino CLI\arduino-cli.exe" upload -p $Port --fqbn arduino:avr:uno --input-dir "d:\elegoo fide\fido_uno_key\build"
if ($LASTEXITCODE -eq 0) {
    Write-Host "Flashing successful!" -ForegroundColor Green
} else {
    Write-Host "Flashing failed. Exit code: $LASTEXITCODE" -ForegroundColor Red
}
