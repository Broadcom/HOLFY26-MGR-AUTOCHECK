# Report Card #52 VMs syncd to ntp.$dom or Main Console

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

$tmp = $Env:temp

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$domain = $args[2]
$target = $hostname + "(" + $ipTarget + ")"	

# check time source
# older machines might require: net time /querysntp
$timeSourceScript = "w32tm /query /configuration"
# Define the tolerance for time delta between local and remote machines
$timeDiffTolerance = 30
$timeTolerance = New-Timespan -Second $timeDiffTolerance
# assuming all the Windows boxes we use have PowerShell (nice that this can be done in a single command line)
$nowTimeScript = 'PowerShell.exe -Command Write-Host (Get-Date).ToUniversalTime()'

# check time source
Try {
	$output1 = RunWinCmd $timeSourceScript ([REF]$result) $ipTarget 'Administrator' $password
	$output1 = $output1.Replace("-", "")
	$output1 = $output1.Replace("', '", "")
	$output1 = $output1.Replace("['", "")
	$output = $output1.Split("\r")
	$next = $false
	Foreach ($line in $output) {
		If ( $next -eq $true ) {
			($source, $junk) = $line.Split(',')			
			Break
		}
		If ( $line -Like "*NtpServer*" ) { $next = $true }
	}
	If ( ($source -like '*10.0.100.1*') -Or ($source -like '*ntp*') -Or ($source -like "*$dom*") ) { 
		Write-Logs "PASS" $target "Windows NTP" "NTP is configured correctly on $hostName to use $source"
	} Else {
		Write-Logs "FAIL" $target "Windows NTP" "NTP is NOT configured correctly on $hostName using $source"
	}
} Catch {
	Write-Logs "FAIL" $target "Windows NTP" "Cannot check Windows time source on $hostname"
}

# check the time difference
Try {
	$output1 = RunWinCmd $nowTimeScript ([REF]$result) $ipTarget 'Administrator' $password
	$output1 = $output1.Replace("', '", "")
	$output1 = $output1.Replace("['", "")
	$output = $output1.Replace("']", "")
	$p = $output.Split()
	$date = $p[1]
	$hour = $p[2]
	$minute = $p[3]
	$second = $p[4]
	$ampm = $p[5]
	$dateString = "${date} ${hour}:${minute}:${second} $ampm"
	$remoteUTC = [datetime]$dateString
	$nowUTC = (Get-Date).ToUniversalTime()
	If ( $remoteUTC -gt $nowUTC ) {
		$timeDiff = New-TimeSpan -Start $nowUTC -End $remoteUTC 
	} Else {
		$timeDiff = New-TimeSpan -Start $remoteUTC -End $nowUTC 
	}
	If ( ($timeDiff -gt $timeTolerance)  ) {
		Write-Logs "FAIL" $target "Windows Time Difference" "Time difference of $timeDiff on $hostName exceeds tolerance. remoteUTC: $remoteUTC localUTC: $nowUTC"
	} Else {
		Write-Logs "PASS" $target "Windows Time Difference" "Time difference of $timeDiff on $hostName is okay. remoteUTC: $remoteUTC localUTC: $nowUTC"
	}
} Catch {
		Write-Logs "FAIL" $target "Windows Time Difference" "Cannot check time on $hostName"
}
