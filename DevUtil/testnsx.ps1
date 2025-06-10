$autocheckModulePath = Join-Path -Path $PSSCriptRoot -ChildPath "../autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

<#
# Overwrite logs - useful in development but do not use for production
Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file
Set-Content -Path $csvDetailFile -Value "" -NoNewline # overwrite existing log file
#>

#$result must be created in order to pass as reference for looping
$result = ''
$hostName = "nsx-mgmt.vcf.sddc.lab"
$ipTarget = "10.0.0.20"

Invoke-Expression "python3 $PSSCriptRoot/../checknsx.py `"$hostName`" $ipTarget > /tmp/output.txt"
$output = Get-Content -Path "/tmp/output.txt"


ForEach ( $line in $output) {
	$lstatus = ""
	#Write-Host "$ctr $line"
	$field = $line.Split("~")
	$lstatus = $field[0]
	$ltarget = $field[1]
	$ltest = $field[2]
	$ldesc = $field[3]
	If ( $lstatus -eq "WARN" ) {
		# need to get the expiration value between "expires
		($licenseDesc, $expiry) = $ldesc.Split(":")
		[int64]$epochExp = $expiry
		$expDate = $epoch.AddMilliSeconds($epochExp)
		#Write-Host $expDate
		If( $expDate -and (($expDate -ge $chkDateMin) -and ($expDate -le $chkDateMax)) ) {
			$lstatus = "PASS"
			$ldesc = "$licenseDesc license on $target is good and expires $expDate"
		} Else {
			$lstatus = "FAIL"
			$ldesc = "$licenseDesc license on $target is bad. Expires on $expDate"
		}	
	}
	If ( $lstatus -ne "" ) { Write-Logs $lstatus $ltarget $ltest $ldesc }
}