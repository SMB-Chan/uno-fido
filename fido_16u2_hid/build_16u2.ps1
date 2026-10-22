# Rebuild fido_16u2_hid.hex from fido_16u2_hid.c using the avr-gcc that ships
# with the Arduino IDE (no separate toolchain install needed).
#
#   powershell -ExecutionPolicy Bypass -File .\fido_16u2_hid\build_16u2.ps1
#
# The committed .hex is only a convenience copy: flash_16u2_fido_hid.ps1 writes
# whatever is in fido_16u2_hid.hex, so run this first after any .c change.
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $here 'fido_16u2_hid.c'
$hex  = Join-Path $here 'fido_16u2_hid.hex'
$elf  = Join-Path $here 'fido_16u2_hid.elf'

# Arduino IDE 2.x / 1.8.x both keep the toolchain under Arduino15.
$toolRoot = Join-Path $env:LOCALAPPDATA 'Arduino15\packages\arduino\tools\avr-gcc'
if (-not (Test-Path $toolRoot)) {
  throw "avr-gcc not found: $toolRoot (install the Arduino AVR board package)"
}
$bin = Get-ChildItem $toolRoot -Directory |
       Sort-Object Name -Descending |
       ForEach-Object { Join-Path $_.FullName 'bin' } |
       Where-Object { Test-Path (Join-Path $_ 'avr-gcc.exe') } |
       Select-Object -First 1
if (-not $bin) { throw "avr-gcc.exe not found under $toolRoot" }

$gcc = Join-Path $bin 'avr-gcc.exe'
$objcopy = Join-Path $bin 'avr-objcopy.exe'
$size = Join-Path $bin 'avr-size.exe'

# ATmega16U2: 16 KB flash, 512 B SRAM. -Os and section garbage collection are
# required: the plain build overflowed SRAM and wedged USB.
& $gcc -mmcu=atmega16u2 -DF_CPU=16000000UL -Os -flto -ffunction-sections -fdata-sections `
       -Wall -Wextra -std=gnu99 -o $elf $src `
       -Wl,--gc-sections -Wl,--relax
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

& $objcopy -O ihex -R .eeprom -R .fuse -R .lock -R .signature $elf $hex
if ($LASTEXITCODE -ne 0) { throw "objcopy failed" }

& $size $elf
Write-Output ""
Write-Output "wrote $hex"
Write-Output "next: powershell -ExecutionPolicy Bypass -File .\fido_16u2_hid\flash_16u2_fido_hid.ps1"
