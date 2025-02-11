

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''
# for non-precious output
$tmp = $Env:temp
 
##############################################################################
##### BEGIN HERE
##############################################################################

Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file

# Report card #12 vCenters reachable
#FQDN(s) of vCenter server(s): also from VCENTERS file in C:\HOL\Resources
Set-Variable -Name "VCENTERS" -Value $(Read-FileIntoArray "VCENTERS")
If ( $vCenters ) { Write-Output "Checking vCenter connections..." }
$vcsToTest = @()
$vcPresent = $false
Foreach ($entry in $vCenters) {
	$login = ""
	($vcserver,$type,$login) = $entry.Split(":")
	If ( $login ) { $vcusers = ,$login + $vcusers } # using the login field, use it first
	$vcsToTest += $vc
	$ctr = 1
	Foreach ($vcuser in $vcusers) {
		$errorVar = Connect-VC $vcserver $vcuser $password ([REF]$result)
		#Write-Output "vcuser: $vcuser errorVar: $errorVar"
		If ( $result -eq "success" ) {
			Write-Logs "PASS" $vcserver "vCenter connection" "$vcserver connection successful as $vcuser"
			$vcPresent = $true
			Break
		} ElseIf ( $ctr -eq $vcusers.length ) {
			Write-Logs "FAIL" $vcserver "vCenter connection" "Failed to connect to server $vcserver $errorVar"
		}
		$ctr++
	}
}

Write-Output "Verifying FreeNAS VMFS datastore are checked by LabStartup..."

Set-Variable -Name "DATASTORES" -Value $(Read-FileIntoArray "DATASTORES")
Foreach ( $line in $datastores ) {
	($s,$d) = $line.Split(":")
	$dsNames += $d
}

$vcDS = Get-Datastore | Where {$_.Type -eq "VMFS"}
Foreach ( $ds in $vcDS ) {
	$vmHost = Get-VMHost -Id $ds.ExtensionData.Host[0].Key
	If ( $vmHost.Model -eq "VMware Mobility Platform" ) { Continue } # skip HCX ghost ESXi hosts and storage
	$diskName = ($ds.ExtensionData.Info.Vmfs.Extent[0]).DiskName
	$displayName = (Get-ScsiLun -CanonicalName $diskName -VMHost $vmHost).ExtensionData.DisplayName
	# verify this is a FreeNAS datastore
	If ( $displayName -Like "*FreeNAS*" ) {
		If ( $dsNames.Contains($ds) ) {
			Write-Logs "PASS" "LabStartup" "Datastore check" "FreeNAS iSCSI datastore $ds was found in C:\hol\Resources\Datastores.txt."
		} Else {
			Write-Logs "FAIL" "LabStartup"  "Datastore check"  "FreeNAS iSCSI datastore $ds is not found in C:\hol\Resources\Datastores.txt. LabStartup needs to check all FreeNAS iSCSI datastores."
		}
	}
}

If ( $vcPresent ) {
	Disconnect-VIServer -Server * -Force -Confirm:$false
} 