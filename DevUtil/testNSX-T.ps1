# need this stuff at a minumum

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = "nsxmgr-01a"
$ipTarget = "192.168.110.42"
$nsxT = $true

If ( $hostName -Like "*nsxmgr*" ) { # counting on this naming convention to give it one more try
	If ( $nsxV ) {
		# do stuff to check NSX-V
		Write-Output "NSX-V detected. Please check settings manually."
		Write-Logs "PASS" $target "$account ssh" "Please check $hostName manually. Please be sure that CORP\Administrator has access to NSX-V."
	} ElseIf ( $nsxT ) {
		Write-Output "NSX-T detected. Checking NSX-T password expiration..."
		Invoke-Expression "$PSScriptRoot\checkNSX-T.ps1 `"$hostName`" $ipTarget nolog" # have to run this one twice to get it to work for some reason
		$nsxMgrCHECK = "$PSScriptRoot\checkNSX-T.ps1 `"$hostName`" $ipTarget"
		Start-Sleep $sleepSeconds 
		Invoke-Expression "$PSScriptRoot\checkNSX-T.ps1 `"$hostName`" $ipTarget" # may have to flag this and run again later in the script
	}
} Else {
	Write-Logs "FAIL" $target "$account ssh" "Cannot ssh as $account on $hostName. Bad ssh configuration or bad $account password. No further checks possible. $errorVar"
}