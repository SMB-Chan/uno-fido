$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 5000
$port.Open()
Start-Sleep -Seconds 2
$port.DiscardInBuffer()

$port.WriteLine("INFO")
Start-Sleep -Milliseconds 300
Write-Output "INFO: $($port.ReadLine())"

$port.WriteLine("CTAP2 04")
Start-Sleep -Milliseconds 300
Write-Output "CTAP2 GetInfo: $($port.ReadLine())"

$port.Close()
