# Flash ATmega16U2 with Native USB HID FIDO2 Firmware via DFU (flip1)
$avrdude = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\bin\avrdude.exe"
$conf = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\etc\avrdude.conf"
$hex = "d:\elegoo fide\fido_16u2_hid\fido_16u2_hid.hex"

& $avrdude -C $conf -c flip1 -p m16u2 -F -e -U "flash:w:${hex}:i"
