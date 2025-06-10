# need this stuff at a minumum

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

# for non-precious output
$tmp = $Env:temp

# clear logs for testing
Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $csvDetailFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file

# autocheck needs to be told the license expiration date for this vPod
$expirationDate = Get-Content "$PSScriptRoot\licenseExpiration.txt"
$licenseExpireDate = Get-Date "$expirationDate 12:00:00 AM"
$chkDateMin = $licenseExpireDate.AddDays(-30)
$chkDateMax = $licenseExpireDate.AddDays(30)

##############################################################################
##### BEGIN HERE
##############################################################################

# need arguments
$hostName = $args[0]
$ipTarget = $args[1]

$target = $hostname + "(" + $ipTarget + ")"

$checkCmd = @"
"test -f /usr/local/bin/vracli && echo True || echo False"
"@

$nf = '$NF'
$vraCmd = @"
"vracli license | grep -i automation | awk '{print $nf}'"
"@

$errorVar = $null
$wcmd = "Echo Y | $plinkPath -ssh $ipTarget -l root -pw VMware1! $checkCmd  2>&1"
[string]$output = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
Write-Output "output: $output errorVar: $errorVar"
If ( $errorVar ) {
	Write-Logs "FAIL" $target "appliance check" "Cannot check for VMware appliance on $hostName $errorVar"
}
If ( $output -eq "True" ) {
	Write-Output "Found vRA appliance $hostName"
	$wcmd = "Echo Y | $plinkPath -ssh $ipTarget -l root -pw VMware1! $vraCmd  2>&1"
	$output = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$vraExpireDate = Get-Date "$output 12:00:00 AM"
	If( $vraExpireDate -and (($vraExpireDate -ge $chkDateMin) -and ($vraExpireDate -le $chkDateMax)) ) {
		Write-Logs "PASS" $target "vRA License" "vRA license on $hostName is good and expires $vraExpireDate"
	} Else {
		Write-Logs "FAIL" $target "vRA License" "vRA license on $hostName is bad and expires $vraExpireDate"
	}
}
