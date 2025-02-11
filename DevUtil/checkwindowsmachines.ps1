# 05-May 2024
# required in order to pass by reference
$result = ""

$autocheckModulePath = Join-Path -Path "$PSSCriptRoot" -ChildPath "autocheckfunctions.psm1"
If ( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else { 
	Write-Output "PSSCriptRoot: $PSSCriptRoot Cannot find AutoCheckfunctions.psm1. Abort."
	Exit
}

##############################################################################
##### BEGIN WINDOWS CHECKS
##############################################################################

#####################################################################################
##### Check Windows machines (valid IP, DHCP and DNS, L1 and L2)
#####################################################################################

# Get Layer 1 Windows VMs
Write-Output "Checking L1 Windows: valid IP, DHCP and DNS..."
$Layer1Windows = @{}
$windowsMachines = @{}
$lines = Get-Content -Path $layerOneInfo
Foreach ($line in $lines) {
	If ( $line -eq "" -Or $line -Like '#*' ) { Continue }
	$IPAddress = ''
	($name,$os,$ipf) = $line.Split(',')
	If ( $os -NotLike '*windows*' ) { Continue }
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ( -Not $ipAddress ) { # if no IPAddress we cannot check further
		Write-Logs "FAIL" $name "L1 IP address" "No IP address for L1 Windows machine. Cannot check."
		Continue # nothing else can be done
	}
	If ( $ipAddress -eq $MCip ) { # Control Center is special
		If ( $WMC ) {
			$dnsName = "controlcenter.$dom"
		} ElseIf ( $LMC ) {
			$dnsName = "mainconsole.$dom"
		}
	}
	
	($nameIP) = VerifyDnsNameIP  $name $ipAddress 'L1' 
	($dnsName,$dnsIP) = $nameIP.Split(":")
	
	$target = $name + "(" + $IPAddress + ")"
	$wm = New-Object -TypeName psobject
	$wm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$wm | Add-Member -MemberType NoteProperty -Name OS -Value ($os.Trim())
	$wm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$wm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$wm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$wm | Add-Member -MemberType NoteProperty -Name Layer -Value "1"
	
	$Layer1Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
	
}

<#
# handy during dev for debugging
If ( Test-Path "layer1windows.csv" ) { Remove-Item -Path "layer1windows.csv" }
Foreach ( $ipTarget in $Layer1Windows.keys ) {
		$Layer1Windows[$ipTarget] | ConvertTo-CSV | Add-Content "layer1windows.csv"
}
#>

#
# Get Layer 2 Windows VMs
#

# re-initialize variables before L2 just to be safe
$name = ""
$dnsName = ""
$ip = ""
$IPAddress = ""

# need vCenter connection
Set-Variable -Name "vCenters" -Value $(Read-ConfigIntoArray "RESOURCES" "vCenters")
$vcPresent = $false
Foreach ($entry in $vCenters) {
	$login = ""
	($vcserver,$type,$login) = $entry.Split(":")
	If ( $login ) { $vcusers = ,$login + $vcusers } # use the login field first if present
	Foreach ($vcuser in $vcusers) {
		Write-Host "Connect-VC $vcserver $vcuser $password"
		$errorVar = Connect-VC $vcserver $vcuser $password ([REF]$result)
		#Write-Output "vcuser: $vcuser errorVar: $errorVar"
		If ( $result -eq "success" ) {
			$vcPresent = $true
			Break
		} ElseIf ( $ctr -eq $vcusers.length ) {
			Write-Output "Failed to connect to server $vcserver $errorVar"
		}
	}
}

$Layer2Windows = @{}
If ( $vcPresent ) { 
	Write-Output "Checking L2 Windows: valid IP, DHCP and DNS..."
	$allvms = Get-VM -ErrorAction SilentlyContinue | where { $_.GuestId -like "*windows*" } # $vm.Guest.OSFullName is blank if powered off so use $vm.GuestId instead.
}

Foreach ($vm in $allvms) {
	$IPAddress = ""
	$name = $vm.Name
	
	$netAdapters = Get-NetworkAdapter -VM $vm
	If ( -Not $netAdapters ) { # nothing we can check on this one
		Write-Logs "INFO" $name "Windows Checks" "$name has no network adapters. Please check manually."
		Continue 
	}
	$wm = New-Object -TypeName psobject
	
	If ( $vm.PowerState -eq "PoweredOff" ) { # power it on if powered off
		$wm | Add-Member -MemberType NoteProperty -Name off -Value $true
		Write-Output "Attempting to Power on L2 Windows VM $name"
		$result = start-L2 $name
		} Else {
		$wm | Add-Member -MemberType NoteProperty -Name off -Value $false
	}
	
	# does it have an IP address?
	# DEBUG
	#Write-Output "$name vm.Guest.IPAdrress: " $vm.Guest.IPAddress
	
	$nameIP = get-L2-IP $name "Windows"
	If ( -Not $nameIP ) { Continue } # Nothing can be done.
	
	# 08/18/2020 added logic for L2 NAT
	($dnsName,$dnsIP,$vmIP,$IPAddress) = $nameIP.Split(":")
	
	If ( ( $dnsIP -ne "unknown" ) -And ($dnsIP -ne $vmIP) ) { 
		Write-Output "NAT detected for $name. vmIP: $vmIP dnsIP: $dnsIP"
	}
	If ( $dnsIP -ne "unknown" ) {
		$IPAddress = $dnsIP
	} ElseIf ( $vmIP -ne "" ) {
		$IPAddress = $vmIP
	} ElseIf ( $IPAddress -eq "" ) {
		Write-Output "No IP address for $name. Skipping."
		restorePowerState $name $wm.Off
		Continue
	}
	$target = $name + "(${IPAddress})"
	#Write-Host "target: $target"
		
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	# DEBUG
	#Write-Output "Get Layer 2 VM $name IPAddress $IPAddress"
	
	$wm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$wm | Add-Member -MemberType NoteProperty -Name OS -Value $vm.Guest.OSFullName
	$wm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$wm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$wm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$wm | Add-Member -MemberType NoteProperty -Name Layer -Value "2"
	$wm | Add-Member -MemberType NoteProperty -Name access -Value $true

	$Layer2Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
	
	# if we powered it on, power it off before we figure out the next Windows L2 VM
	restorePowerState $name $wm.Off
	
} # End Get Layer2 Windows VMs

<#
# handy during dev for debugging
If ( Test-Path "layer2windows.csv" ) { Remove-Item -Path "layer2windows.csv" }
Foreach ( $ipTarget in $Layer2Windows.keys ) {
		$Layer2Windows[$ipTarget] | ConvertTo-CSV | Add-Content "layer2windows.csv"
}
#>

##############################################################################
#####  BEGIN WINDOWS CHECKS LAYER ONE AND LAYER TWO
#####
#####    Windows firewall, activation, Chrome updates, 
#####	password aging, NTP, time delta, VMXNET3(2012), 
#####	skipRestart (Win7, Win2K3 and Win2k8)
##############################################################################

# initialize the removeWindowsMachines array
$removeWindowsMachines = @()

# BEGIN Windows checks loop (Layer 1 and Layer 2)
Write-Output "Checking Windows firewall, activation, Chrome updates, password aging, NTP, time delta, VMXNET3(2012), skipRestart (Win7, Win2K3 and Win2k8) ..."

Foreach ($ipTarget in $windowsMachines.keys) {  # this is the windows check loop. power on, do all checks, power off
	$errorVar = $null
	$name = $windowsMachines[$ipTarget].Name
	$hostName = $windowsMachines[$ipTarget].dnsName
	#Write-Host "name: $name hostName: $hostName"
	If ( $hostname -eq "" ) { $hostName = $name } # if not in DNS use the Name instead
	$target = $name + "(${IPAddress})"
	#Write-Host "target: $target"
	$os = $windowsMachines[$ipTarget].OS
	If ( $windowsMachines[$ipTarget].Layer -eq "2" ) { $vm = Get-VM -Name $name }
	
	#DEBUG
	#Write-Output "DEBUG ipTarget $ipTarget  hostName $hostName"
	If ( $ipTarget -eq "" ) {
		Write-Output "Empty ipTarget for $hostName. Adding to removeWindowsMachines"
		$removeWindowsMachines += $ipTarget
		Continue
	}
	
	# Power on L2 Windows machine for checks then power off when complete
	If ( $windowsMachines[$ipTarget].Off ) { # has to be Layer 2
		Write-Output "Powering on L2 Windows VM $hostName to perform Windows checks..."
		$result = start-L2 $name
		If ( $snap -ne $null ) {
			$snap = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
		}
		$fwCtr = 0
		While ( $true ) {
			If ( $fwCtr -ge 5 ) {  # opportunity to use Invoke-VMScript
				$windowsMachines[$ipTarget].access = $false
				Write-Logs "FAIL" $target "L2 Windows Access" "No ping response on L2 $target after power on. Please check firewall manually."
				Write-Output "Powering off L2 machine $hostName since no access after power on..."
				$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false
				$removeWindowsMachines += $ipTarget
				Break
			}
			
			#DEBUG
			#Write-Host "ipTarget $ipTarget"
			If ( !$ipTarget ) {
				($junk,$ipTarget) = $target.Split('(')
				$ipTarget = $ipTarget.Trim(')')
				Write-Output "PowerShell has lost it's mind on $target. The ipTarget variable is NULL and it should NOT be."
				Write-Output "Skipping tests for $target..."
				Write-Logs "INFO" $target "PowerShell weirdness" "ipTarget variable is NULL."
				Break
			}
			If ( $psVersion -ge 6 ) { # current PowerShell support
				If ( Test-Connection -TargetName $ipTarget -Quiet ) { Break	}
			} Else { # old versions (why using?)
				If ( Test-Connection -ComputerName $ipTarget -Quiet ) { Break	} 
			}
			
			Start-Sleep $sleepSeconds
			$fwCtr++
		} 
	}
	If ( $windowsMachines[$ipTarget].access -eq $false ) { # only false at this point if L2 power on didn't help so just skip it. (no ping)
		Continue
	} 
	
	# Report Card #23 All Windows OS firewalls disabled
	Write-Output "checkWindowsFirewall.ps1 $hostName $ipTarget"
	Invoke-Expression "$PSScriptRoot/checkWindowsFirewall.ps1 `"$hostName`" $ipTarget"
	#Start-Sleep $sleepSeconds
	# check output.txt and add to remove Windows machines arrary
	If ( Test-Path "/tmp/output.tst" ) {
		$output1 = Get-Content -Path "/tmp/output.txt"
		Foreach ( $line in $output ) {
			If ( $line -like '*cannot check*' ) { # cannot reach this machine (firewall on?)
				$windowsMachines[$ipTarget].access = $false
				If ( $windowsMachines[$ipTarget].off ) { 
					$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false
				}
				$removeWindowsMachines += $ipTarget
				Break
			}
		}
	}
	If ( $windowsMachines[$ipTarget].access -eq $false ) { Continue } # probably firewall issue. nothing we can do to check unless Invoke-VMScript (can ping but cannot get in to check firewall)
	
	# Report Card #29 Windows OS license ID changed from default
	Invoke-Expression "$PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget nolog" # first run always fails for some reason
	Start-Sleep $sleepSeconds
	
	#43 Check for updates: Never (Windows task Google check for updates disabled)
	Invoke-Expression "$PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget nolog" # first run always fails for some reason
	Start-Sleep $sleepSeconds

	# Report Card #65 Include skipRestart utility if Win7/2K3/2k8
	If ( ($os -like "*2008*") -or ($os -like "*2003*") -or ($os -like "*Windows*7*") ) {
		Write-Host checkSkipRestart.ps1
		Invoke-Expression "$PSScriptRoot/checkSkipRestart.ps1 `"$hostName`" $ipTarget"
	} Else {
		Write-Logs "PASS" $target "skipRestart Win7/2K3/2k8" "$hostName with OS $os does not need skipRestart."
	}
	Start-Sleep $sleepSeconds

	# Report Card #46 passwords set to NEVER expire
	If ( $ipTarget -eq "$MCip" -And $WMC ) {
		Write-Host "$PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget VCF"
		Invoke-Expression "$PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget VCF" # DC is special case
	} Else {
		Write-Host "$PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "$PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget"
	}
	Start-Sleep $sleepSeconds

	# Report Card #52 VMs syncd to ntp.corp.vmbeans.com or Main Console
	If ( $ipTarget -ne "$MCip" -And $ntpdOK ) { # Checking the Main Console makes no sense
		Write-Host "$PSScriptRoot/checkWindowsTime.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "$PSScriptRoot/checkWindowsTime.ps1 `"$hostName`" $ipTarget"
		Start-Sleep $sleepSeconds
	}

	# Report Card #32 Use VMXNET3 adpater on all Windows 2012 VMs
	If ($windowsMachines[$ipTarget].OS -like '*2012*') {
		Write-Host "$PSScriptRoot/checkWindows2012vmxnet3.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "$PSScriptRoot/checkWindows2012vmxnet3.ps1 `"$hostName`" $ipTarget"
		Start-Sleep $sleepSeconds
	}

	#62 Desktop shortcut names not truncated
	Write-Host "$PSScriptRoot/checkWindowsShortCuts.ps1 `"$hostName`" $ipTarget"
	Invoke-Expression "$PSScriptRoot/checkWindowsShortCuts.ps1 `"$hostName`" $ipTarget"
	Start-Sleep $sleepSeconds 

	# Report Card #29 Windows OS license ID changed from default
	Write-Host "$PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget log"
	Invoke-Expression "$PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget log" # hopefully this second run works
	Start-Sleep $sleepSeconds
	
	#43 Check for updates: Never (Windows task Google check for updates disabled)
	Write-Host "$PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget log"
	Invoke-Expression "$PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget log" # hopefully this second run works
	Start-Sleep $sleepSeconds
	
	# if we powered on the machine, double check that it is powered off
	If ($WindowsMachines[$ipTarget].Off) {
		Write-Output "End of Windows checks for $hostName. Powering off $hostName..."
		restorePowerState $name $wm.Off
	}

} # END Windows check loop

# remove the bad and unreachable Windows machines - no further testing
Foreach ($ipTarget in $removeWindowsMachines) {
	$hostName = $windowsMachines[$ipTarget].Name
	$target = $hostName + "(" + $ipTarget + ")"
	Write-Output "Removing $target"
	Write-Logs "FAIL" $target "Windows checks" "Unable to check $target. Please check manually as needed."
	$windowsMachines.Remove($ipTarget)
	If ( $Layer1Windows[$ipTarget] ) { $Layer1Windows.Remove($ipTarget) }
	If ( $Layer2Windows[$ipTarget] ) { $Layer2Windows.Remove($ipTarget) }
}

##############################################################################
##### END WINDOWS CHECKS
##############################################################################
