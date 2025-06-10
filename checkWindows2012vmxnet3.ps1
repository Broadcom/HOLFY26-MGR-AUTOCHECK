#32 Use VMXNET3 adpater on all Windows 2012 VMs

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$target = $hostname + "(" + $ipTarget + ")"	


$ipconfigScript = "ipconfig /all"

Try {
	$output1 = RunWinCmd $ipconfigScript ([REF]$result) $ipTarget 'Administrator' $password
	$output1 = $output1.Replace("-", "")
	$output1 = $output1.Replace("', '", "")
	$output1 = $output1.Replace("['", "")
	$output = $output1.Split("\r")
	$ctr = 0
	#ForEach ( $line in $output ) {
	#	Write-Host "$ctr $line"
	#	$ctr++
	#}
	#Exit 0
	$adapterFlag = $false
	$macFlag = $false
	Foreach ($line in $output) {
		If ( $line -eq "" ) { Continue }
		If ( $macFlag ) {
			$mac = $line
			Break
		}
		If ( $adapterFlag -And ( $line -Like "*Ethernet Adapter*" ) ) { $nic = $line
		} ElseIf ( $adapterFlag -And $line -Like "*Physical Address*" ) { $macFlag = $true }
		If ( $line -like "*Description*" ) { $adapterFlag = $true }
	}	
		
			
	If ($mac -like '*005056*' ) {
		If ($nic -like '*vmxnet3*' ) {
			Write-Logs "PASS" $target "Windows 2012 VMXNET3" "Windows 2012 machine $hostName is using VMXNET3 network adapter."
		} Else {
			Write-Logs "FAIL" $target "Windows 2012 VMXNET3" "Windows 2012 machine $hostName is using $nic network adapter. "
		}
	}
} Catch {
	Write-Logs "FAIL" $target "Windows 2012 VMXNET3" "Cannot check Windows 2012 VMXNET3 on $hostname"
}
