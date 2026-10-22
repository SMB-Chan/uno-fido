# Restore ATmega16U2 back to Official Arduino Uno R3 USB-Serial Firmware via DFU (flip1)
$avrdude = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\bin\avrdude.exe"
$conf = "$env:LOCALAPPDATA\Arduino15\packages\arduino\tools\avrdude\8.0.0-arduino1\etc\avrdude.conf"
$origHex = "$env:LOCALAPPDATA\Arduino15\packages\arduino\hardware\avr\1.8.8\firmwares\atmegaxxu2\arduino-usbserial\Arduino-usbserial-atmega16u2-Uno-Rev3.hex"

& $avrdude -C $conf -c flip1 -p m16u2 -F -e -U "flash:w:${origHex}:i"
