$autocheckModulePath = "$PSSCriptRoot\..\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''
# for non-precious output
$tmp = $Env:temp
 
##############################################################################
##### BEGIN HERE
##############################################################################

# need to maintain vcVersion and build number hash from the base templates
#$vcVersion = @{
#"6.7.0" = "15129973"
#"7.0.0" = "15952498"
#}
#Export-ModuleMember -Variable vcVersion

Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file

# need to maintain esxVersion and build number hash from the base templates
#$esxVersion = @{
#"6.7.0" = "15160138"
#"7.0.0" = "15843807"
#}

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

##### check vCenter version and build numbers
$function = "vCenter build"
If ( $vcPresent ) { 
	Write-Output "Checking vSphere version/build configuration..."
	ForEach ( $s in $global:DefaultVIServers ) {
		$name = $s.name
		$version = $s.Version
		$build = $s.Build
		If ( $vcVersion[$version] -eq $build ) {
			Write-Logs "PASS" $name $function "$name is running vCenter $version build $build which is a standard HOL build."
		} Else {
			Write-Logs "WARN" $name $function "$name is running vCenter $version build $build which is not a standard HOL build."
		}
	} 	
	$allhosts = Get-VMHost -ErrorAction SilentlyContinue
} # end vCenter version and build numbers

# this will also identify stand-alone ESXi hosts
Set-Variable -Name "ESXIHOSTS" -Value $(Read-FileIntoArray "ESXIHOSTS")

##### check vESXi version and build numbers
$function = "vESXi Build"
$prevBuild = ""
Foreach ($h in $allhosts) {
	If ( $h.model -eq "VMware Mobility Platform" ) { Continue } # skipping the "ghost" ESXi hosts that HCX uses
	$version = $h.version
	$build = $h.build
	#Write-Output "$h version: $version build: $build"
	If ( ( $build -ne $prevBuild ) -And ( $prevBuild -ne "" ) ) {
		$diffBuilds = $True
	}

	If ( $esxVersion[$version] -eq $build ) {
		Write-Logs "PASS" $h.name $function "$h.name is running ESXi $version build $build which is a standard HOL build."
	} Else {
		Write-Logs "WARN" $h.name $function "$h.name is running ESXi $version build $build which is not a standard HOL build."
	}
	$prevBuild = $build

}

If ( $diffBuilds ) {
		Write-Logs "WARN" $h.name $function "ESXi hosts are running different builds. There might be vMotion compatibility issues."
} # end Check vESXi version and build


If ( $vcPresent ) {
	Disconnect-VIServer -Server * -Force -Confirm:$false
} 