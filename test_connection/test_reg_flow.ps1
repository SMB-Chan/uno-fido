$port = New-Object System.IO.Ports.SerialPort "COM5", 115200, "None", 8, "One"
$port.DtrEnable = $true
$port.RtsEnable = $true
$port.ReadTimeout = 20000
$port.Open()

Start-Sleep -Seconds 2
Write-Output "Boot output: $($port.ReadExisting())"

# 1. Send INFO
$port.WriteLine("INFO")
Start-Sleep -Milliseconds 300
Write-Output "INFO resp: $($port.ReadExisting())"

# 2. Send REG
$chal = "bcb6e20a0f441ebff2f1324680a3e59334eb0f228b92d1cd9f5115b7e75eb5d8"
$rpid = "2ddf4f04601ea71f346abbb525f7822377aaa7ae961647d1dabe9d69fc22c942"
$port.WriteLine("REG $chal $rpid")
Start-Sleep -Milliseconds 500
Write-Output "REG initial resp: $($port.ReadExisting())"

# 3. Send Virtual Touch 'T'
$port.Write("T")
Start-Sleep -Milliseconds 500
Write-Output "After Touch resp: $($port.ReadExisting())"

# 4. Wait 10 seconds for P-256 keygen + sign
Start-Sleep -Seconds 10
Write-Output "REG final resp: $($port.ReadExisting())"

$port.Close()
