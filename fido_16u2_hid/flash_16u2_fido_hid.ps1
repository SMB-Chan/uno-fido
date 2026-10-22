# Flash ATmega16U2 with Native USB HID FIDO2 Firmware via DFU (flip1)
$avrdude = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\bin\avrdude.exe"
$conf = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\etc\avrdude.conf"
# Rebuild first: .\build_16u2.ps1 (the .c changed since this hex was produced).
$hex = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'fido_16u2_hid.hex'
if (-not (Test-Path $hex)) { throw "hex not found: $hex (run build_16u2.ps1)" }

& $avrdude -C $conf -c flip1 -p m16u2 -F -e -U "flash:w:${hex}:i"
