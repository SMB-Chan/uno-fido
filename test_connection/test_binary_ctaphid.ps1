$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 5000
$port.Open()
Start-Sleep -Seconds 2
$port.DiscardInBuffer()

# Test Binary CTAPHID_INIT (0x86) frame: 0xAA 0x55 + [CID=FFFFFFFF, CMD=0x86, LEN=0x0008, Nonce=1122334455667788]
$pkt = New-Object byte[] 66
$pkt[0] = 0xAA
$pkt[1] = 0x55
$pkt[2] = 0xFF; $pkt[3] = 0xFF; $pkt[4] = 0xFF; $pkt[5] = 0xFF # Broadcast CID
$pkt[6] = 0x86 # CTAPHID_INIT
$pkt[7] = 0x00; $pkt[8] = 0x08 # Length 8
$pkt[9] = 0x11; $pkt[10] = 0x22; $pkt[11] = 0x33; $pkt[12] = 0x44
$pkt[13] = 0x55; $pkt[14] = 0x66; $pkt[15] = 0x77; $pkt[16] = 0x88

$port.Write($pkt, 0, 66)
Start-Sleep -Milliseconds 300

$rx = New-Object byte[] 66
$read = $port.Read($rx, 0, 66)
$hex = ($rx[0..25] | ForEach-Object { $_.ToString("X2") }) -join " "
Write-Output "CTAPHID_INIT Response ($read bytes): $hex"

$port.Close()
