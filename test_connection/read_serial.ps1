$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 3000
$port.Open()
Start-Sleep -Seconds 2
$line = $port.ReadLine()
Write-Output "Arduino Output: $line"
$port.Close()
