$autocheckModulePath = "$PSSCriptRoot\..\autocheckfunctions.psm1"
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

# this will also identify stand-alone ESXi hosts
Set-Variable -Name "ESXIHOSTS" -Value $(Read-FileIntoArray "ESXIHOSTS")

$allhosts = Get-VMHost -ErrorAction SilentlyContinue

##### check vESXi unique MAC addresses
$macHash = @{}
$function = "vESXi MAC"
Foreach ($h in $allhosts) {
	If ( $h.model -eq "VMware Mobility Platform" ) { Continue } # skipping the "ghost" ESXi hosts that HCX uses
	$nics = Get-VMHostNetworkAdapter -VMHost $h
	Foreach ( $nic in $nics ) {
		$mac = $nic.Mac
		$checkHash = $macHash[$mac]
		If ( $macHash[$mac] ) {
			($pNic, $hName) = $macHash[$mac].Split()
			Write-Logs "FAIL" $h.Name $function "$h $nic has same MAC address as $pNic on $hName. Reset MAC on $pNic is REQUIRED."
		} Else {
			$deviceName = $nic.DeviceName
			$hName = $h.Name
			$macHash[$mac] = "$deviceName $hName"
		}
	}
}

If ( $vcPresent ) {
	Disconnect-VIServer -Server * -Force -Confirm:$false
} 