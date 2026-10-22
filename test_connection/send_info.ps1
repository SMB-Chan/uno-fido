$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 5000
$port.Open()

# Wait for boot
Start-Sleep -Seconds 2
$port.DiscardInBuffer()

# Send INFO
$port.WriteLine("INFO")
Start-Sleep -Milliseconds 500

$resp = $port.ReadLine()
Write-Output "Response: $resp"
$port.Close()
