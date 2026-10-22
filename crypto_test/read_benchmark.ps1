$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 25000
$port.Open()

# Discard initial reboot bytes
Start-Sleep -Milliseconds 500
$port.DiscardInBuffer()

# Wait for full test
Start-Sleep -Seconds 18

$output = $port.ReadExisting()
Write-Output $output
$port.Close()
