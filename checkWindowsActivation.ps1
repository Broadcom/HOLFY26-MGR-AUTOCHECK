# checkWindowsActivation.ps1 16-April 2024

# Report Card #29 Windows OS license ID changed from default - exclude Main Console

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]

If ( $args[2] -eq "nolog" ) {
	$log = $false
} Else {
	$log = $true
}
$target = $hostname + "(" + $ipTarget + ")"	

$LicenseStatus = @("Unlicensed","Licensed","OOB Grace", "OOT Grace","Non-Genuine Grace","Notification","Extended Grace")
$activationScript = @"
"Powershell.exe -Command \"Write-Output (Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object {\`$`_.PartialProductKey -And \`$`_.Name -Match 'Windows'}).LicenseStatus\""
"@

"/usr/bin/python3 /home/holuser/autocheck/runwincmd.py $ipTarget Administrator $password $activationscript" | Set-Content /tmp/runcmd.sh


Try {
	$errorVar = $null
	$output1 = Invoke-Expression -Command "/bin/sh /tmp/runcmd.sh" -ErrorVariable errorVar	
	#Write-Host "output1: $output1"
	
	($junk, $out) = $output1.Split("[")
	$output = $out.SubString(1, 1)
	$activationStatus = $LicenseStatus[$output]
	($status, $junk) = $activationStatus.Split()
	If ( $activationStatus -notmatch "Licensed" ) {
		If ( $log ) { Write-Logs "FAIL" $target "Windows Activation" "Windows is not activated on machine $hostName License status: $status" }
	} Else {
		If ( $log ) { Write-Logs "PASS" $target "Windows Activation" "Windows machine $hostName is activated. License status: $status" }
	}
} Catch {
	Write-Host "error"
	If ( $log ) { Write-Logs "FAIL" $target "Windows Activation" "Cannot check Windows activation on $hostname" }
}
