
# use for Linux/Windows L1/L2 all the same


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


#####################################################################################
##### Check Linux machines (PuTTY sessions, DNS, valid IP and SSH service, L1 and L2)
#####################################################################################

# requires vCenter connection so keeping local to main script
# Report card #31 Static IPs on Linux VMs
# Report card #47 PuTTY entry for all Linix VMs: no password prompt
# Report card #50 no PuTTY session for vPodRouter

# Get Layer 1 Linux and Other VMs
Write-Output "Checking L1 Linux: PuTTY sessions, valid IP, DHCP, DNS, router and SSH service..."
$Layer1Linux = @{}
$linuxMachines = @{}
$lines = Get-Content -Path $layerOneInfo
Foreach ($line in $lines) {
	If ( $line -eq "" ) { Continue }
	$IPAddress = ''
	($name,$os,$ipf) = $line.Split(',')
	If ( $os -Like '*windows*' ) { Continue }
	If ( $name -like '*vPodRouter*' ) { # vPodRouterHOL is special
		$name = 'router'
	}
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ( $ipAddress -eq '192.168.110.60' ) { Continue } # skip FreeNAS storage appliance
	If ( -Not $ipAddress ) { # if no IPAddress we cannot check further
		Write-Logs "FAIL" $name "L1 IP address" "No IP address for L1 Linux machine $name. Cannot check."
		Continue # nothing else can be done
	}
	If ( $Layer1Linux[$ipAddress] ) { Continue }  # duplicate entry so skip it
	
	($nameIP) = VerifyDnsNameIP  $name $ipAddress 'L1' 
	($dnsName,$dnsIP) = $nameIP.Split(":")
	
	$target = $name + "(" + $IPAddress + ")"
	$lm = New-Object -TypeName psobject
	$lm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$lm | Add-Member -MemberType NoteProperty -Name OS -Value ($os.Trim())
	$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$lm | Add-Member -MemberType NoteProperty -Name sshRoot -Value "unknown"
	
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	# check for SSH service response
	Test-TcpPortOpen -Server $IPAddress -Port '22' -Result ([REF]$result)
	If( $result -ne "success" ) {
		Write-Logs "FAIL" $target "No SSH answer" "No SSH response on $IPAddress cannot perform checks requiring SSH"
		$ssh = $false
	} Else {
		$ssh = $true
	}
	$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
	$lm | Add-Member -MemberType NoteProperty -Name account -Value "root"
	
	$Layer1Linux[$IPAddress] = $lm
	$linuxMachines[$IPAddress] = $lm
} # End get L1 Linux machines

# re-initialize variables before L2 just to be safe
$name = ""
$dnsName = ""
$ip = ""
$IPAddress = ""

#Foreach ( $ipTarget in $linuxMachines.keys ) {
#	$linuxMachines[$ipTarget]
#}

# Get Layer 2 Linux and Other VMs
$Layer2Linux = @{}
If ( $vcPresent ) { 
	Write-Output "Checking L2 Linux: PuTTY sessions, valid IP, DHCP, DNS and SSH service..."
	$allvms = Get-VM -ErrorAction SilentlyContinue
}

Foreach ($vm in $allvms) {
	If( $vm.GuestId -notmatch 'linux|ubuntu|debian|centos|sles|redhat|photon|rhel|other' ) { Continue }
	
	$IPAddress = ""
	$name = $vm.Name
	
	$netAdapters = Get-NetworkAdapter -VM $vm
	If ( -Not $netAdapters ) { # nothing we can check on this one
		Write-Logs "INFO" $name "Linux Checks" "Layer 2 VM $name has no network adapters. Please check manually."
		Continue 
	}
	$lm = New-Object -TypeName psobject
	
	If ( $vm.PowerState -eq "PoweredOff" ) { # power it on if powered off
		$lm | Add-Member -MemberType NoteProperty -Name Off -Value $true
		Write-Output "Powering on L2 Linux VM $name"
		$result = start-L2 $name
	} Else {
		$lm | Add-Member -MemberType NoteProperty -Name Off -Value $false
	}
	
	$nameIP = get-L2-IP $name "Linux"
	If ( -Not $nameIP ) { Continue } # Nothing can be done.
	# 08/18/2020 added logic for L2 NAT
	($dnsName,$dnsIP,$vmIP) = $nameIP.Split(":")
	If ( ($dnsIP -ne "") -And ($dnsIP -ne $vmIP) ) { 
		Write-Output "NAT detected for $name. vmIP: $vmIP dnsIP: $dnsIP"
	}
	If ( $dnsIP ) {
		$IPAddress = $dnsIP
	} ElseIf ( $vmIP ) {
		$IPAddress = $vmIP
	} Else {
		Write-Output "No IP address for $name. Skipping."
		restorePowerState $name $wm.Off
		Continue
	}
	$target = $name + "(" + $IPAddress + ")"
		
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	Write-Output "$dnsName $dnsIP $IPAddress"
	
	# check for SSH service response
	If ( $IPAddress ) {
		If ( $Layer2Linux[$IPAddress] ) { Continue } # seems like getting $allvms includes some duplicates
		$sshCtr = 0
		Do {
			If ( $sshCtr -ge 5 ) {  # opportunity to use Invoke-VMScript
				$ssh = $false
				Write-Logs "FAIL" $target "SSH answer" "No SSH response at $IPAddress so cannot perform Linux checks requiring SSH. Please check this machine manually."
				Break
			}
			Test-TcpPortOpen -Server $IPAddress -Port '22' -Result ([REF]$result)
			If( $result -eq "success" ) {
				$ssh = $true
				Write-Logs "PASS" $target "SSH answer" "Received an SSH response on $IPAddress so Linux checks will be performed. Thanks!"
				Break
			} 
			Start-Sleep $sleepSeconds
			$sshCtr++
		} While ( $result -ne "success" )
		$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
	} Else {
		$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $false
	}
	$lm | Add-Member -MemberType NoteProperty -Name account -Value "root"
	$lm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$lm | Add-Member -MemberType NoteProperty -Name OS -Value $vm.GuestId
	$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$lm | Add-Member -MemberType NoteProperty -Name sshRoot -Value "unknown"
	
	If ( $IPAddress ) {
		$Layer2Linux[$IPAddress] = $lm
		$linuxMachines[$IPAddress] = $lm
	}
	
	# if we powered it on, power it off before we figure out the next Linux L2 VM
	restorePowerState $name $lm.Off
	
} # End get L2 Linux machinesL2 Linux machines

# Check PuTTY entries
Foreach ($session in $puttySessions) {

	#$ps = New-Object -TypeName psobject
	$puttyHost = ""
	$puttyIP = ""
	$parts = ($session.Name).split('\')
	$sessionName = $parts[$parts.length-1] # use the last part of the Registry key
	If ( $sessionName -match 'Default') { Continue }	# skip Default
	$hostName = $session.getValue('HostName')
	If ( $hostName -Like '*@*' ) { 
		($account, $puttyHost) = $hostName.Split('@') # if $account - correct HOL convention
	} Else {
		$puttyHost = $hostName
		$puttyUnProperty = Get-ItemProperty -Path "$puttyPath\$sessionName" -Name "UserName"
		$puttyUserName = $puttyUnProperty.UserName # if puttyUserName - incorrect HOL convention but acceptable (if neither - FAIL)
	}
	If ( $puttyHost -Match $IPRegex ) { # is it an IP?
		$puttyIP = $puttyHost
	} Else {
		If ( -Not ($puttyHost -Like "*.corp.local") ) { $puttyHost = $puttyHost + ".corp.local" }
		$puttyIP = Check-DNS $puttyHost ([REF]$result) # not an IP so check puttyHost against DNS - this SHOULD be found
		#Write-Output "$puttyHost dnsIP: $puttyIP"
		If ( $result -ne "success" ) { # this is LIKELY a PuTTY session that should be deleted
			$found = $false
			#Write-Output "Checking PuTTY $hostName..."
			Foreach ( $ip in $linuxMachines.keys ) {
				$dnsName = $linuxMachines[$ip].dnsName
				If ( ($dnsName -like  "*$puttyHost*") -Or ($puttyHost -eq $dnsName)) {
					$found = $true
					Break
				} 	
			}
			If ( -Not $found ) {
				Write-Logs "INFO" "PuTTY Session" "Valid PuTTY Session" "DNS lookup failed for $puttyHost. Perhaps this PuTTY session should be deleted."
			}
		}
	}
	If ( $puttyIP -like "192.168.*.1" ) { # don't want a PuTTY session for the router in most cases
		Write-Logs "FAIL" $sessionName "PuTTY Convention" "HOL does not want a PuTTY session to the vPodRouter. Please delete unless an exception is granted."
		Continue
	}
	#Write-Output "puttyIP: $puttyIP linuxMachines[puttyIP]: " $linuxMachines[$puttyIP]
	If ( $puttyIP -And $linuxMachines[$puttyIP] ) { # found it
		# take note that this Linux machine has a PuTTY session
		$linuxMachines[$puttyIP] | Add-Member -MemberType NoteProperty -Name PuTTY -Value $true -Force
		If ( $account ) {
			# pass and following HOL convention
			Write-Logs "PASS" $sessionName "PuTTY Convention" "PuTTy session $sessionName uses proper HOL convention account@host."
		} ElseIf ( $puttyUserName ) {
			# pass but not HOL convention
			Write-Logs "INFO" $sessionName "PuTTY Convention" "PuTTy session $sessionName does NOT use the proper HOL convention account@host but does specify $puttyUserName as default."
		} Else {
			# INFO no account specified
			Write-Logs "INFO" $sessionName "PuTTY Convention" "PuTTy session $sessionName does NOT use the proper HOL convention account@host and no account name is specified."
		}
		# compare the name used in $lnuxMachines to $puttyHost
		If ( $puttyHost -ne $linuxMachines[$puttyIP].name ) {
			$lmName = $linuxMachines[$puttyIP].name
			If ( $puttyHost -ne "$lmName.corp.local" ) {
				Write-Logs "INFO" $sessionName "PuTTY Conventions" "PuTTY session $sessionName uses $puttyHost instead of $lmName."
			}
		}
	} Else {
		# This could be a stand alone L2 VM on ESXi or possibly on another hypervisor (KVM or Hyper-V)
		# check for SSH service response
		$target = $hostname + '(' + $puttyIP + ')'
		Test-TcpPortOpen -Server $puttyIP -Port '22' -Result ([REF]$result)
		If( $result -ne "success" ) {
			Write-Logs "INFO" $target "PuTTY Session" "Did not find Linux machine for $sessionName and no ssh response. Perhaps this PuTTY session should be deleted?"
		} Else {
			$ssh = $true
			Write-Logs "PASS" $target "SSH answer" "Received an SSH response on $puttyIP so Linux checks will be performed. Thanks!"
			# check DNS
			($nameIP) = VerifyDnsNameIP  $hostname $puttyIP 'L2' 
			($dnsName,$dnsIP) = $nameIP.Split(":")
			# add this machine to the list for checking
			$lm = New-Object -TypeName psobject
			$lm | Add-Member -MemberType NoteProperty -Name Name -Value $hostname
			$lm | Add-Member -MemberType NoteProperty -Name OS -Value "Linux" # don't really know at this point
			$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
			$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $puttyIP
			$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
			$lm | Add-Member -MemberType NoteProperty -Name sshRoot -Value "unknown"
			$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
			$lm | Add-Member -MemberType NoteProperty -Name account -Value $account
			$lm | Add-Member -MemberType NoteProperty -Name PuTTY -Value $true -Force
			$Layer2Linux[$puttyIP] = $lm
			$linuxMachines[$puttyIP] = $lm
		}
		#$linuxMachines[$puttyIP] | Add-Member -MemberType NoteProperty -Name PuTTY -Value $false -Force
		#Write-Output "sessionName: $sessionName puttyIP: $puttyIP"
	}
} # End Foreach PuTTY sessions

# Does every Linux machine (except the router) have a PuTTY session?
Foreach ( $ipTarget in $linuxMachines.keys ) {
	If ( (-Not $linuxMachines[$ipTarget].PuTTY ) -And ($ipTarget -NotLike "192.168.*.1") ) {
		$hostName = $linuxMachines[$ipTarget].Name
		$target = $hostName + "(" + $ipTarget + ")"
		Write-Logs "INFO" $target "PuTTY Entry" "No PuTTY entry for $target."
	}		
}

#####################################################################################
##### Check Windows machines (valid IP, DHCP and DNS, L1 and L2)
#####################################################################################
# Get Layer 1 Windows VMs
Write-Output "Checking L1 Windows: valid IP, DHCP and DNS..."
$Layer1Windows = @{}
$windowsMachines = @{}
$lines = Get-Content -Path $layerOneInfo
Foreach ($line in $lines) {
	If ( $line -eq "" ) { Continue }
	$IPAddress = ''
	($name,$os,$ipf) = $line.Split(',')
	If ( -Not ($os -Like '*windows*') ) { Continue }
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ( -Not $ipAddress ) { # if no IPAddress we cannot check further
		Write-Logs "FAIL" $name "L1 IP address" "No IP address for L1 Windows machine. Cannot check."
		Continue # nothing else can be done
	}
	If ( $ipAddress -eq '192.168.110.10' ) { # Control Center is special
		$dnsName = 'controlcenter.corp.local'
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
	
	$Layer1Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
}


# Get Layer 2 Windows VMs
$Layer2Windows = @{}
If ( $vcPresent ) { 
	Write-Output "Checking L2 Windows: valid IP, DHCP and DNS..."
	$allvms = Get-VM -ErrorAction SilentlyContinue | where { $_.GuestId -like "*windows*" } # $vm.Guest.OSFullName is blank if powered off so use 4vm.GuestId instead.
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
		$wm | Add-Member -MemberType NoteProperty -Name off -Value $true
	}
	
	# does it have an IP address?
	# DEBUG
	#Write-Output "$name vm.Guest.IPAdrress: " $vm.Guest.IPAddress
	
	$nameIP = get-L2-IP $name "Windows"
	If ( -Not $nameIP ) { Continue } # Nothing can be done.
	# 08/18/2020 added logic for L2 NAT
	($dnsName,$dnsIP,$vmIP) = $nameIP.Split(":")
	If ( ($dnsIP -ne "") -And ($dnsIP -ne $vmIP) ) { 
		Write-Output "NAT detected for $name. vmIP: $vmIP dnsIP: $dnsIP"
	}
	If ( $dnsIP ) {
		$IPAddress = $dnsIP
	} ElseIf ( $vmIP ) {
		$IPAddress = $vmIP
	} Else {
		Write-Output "No IP address for $name. Skipping."
		restorePowerState $name $wm.Off
		Continue
	}
	$target = $name + "(" + $dnsIP + ")"
		
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	
	# DEBUG
	#Write-Output "Get Layer 2 VM $name IPAddress $IPAddress"
	
	$wm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$wm | Add-Member -MemberType NoteProperty -Name OS -Value $vm.GuestId
	$wm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$wm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$wm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$wm | Add-Member -MemberType NoteProperty -Name access -Value $true
	$Layer2Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
	
	# if we powered it on, power it off before we figure out the next Windows L2 VM
	restorePowerState $name $wm.Off
	
} # End Get Layer2 Windows VMs

If ( $vcPresent ) {
	Disconnect-VIServer -Server * -Force -Confirm:$false
} 

Foreach ( $ipTarget in $linuxMachines.keys ) {
	$linuxMachines[$ipTarget]
}

Foreach ( $ipTarget in $windowsMachines.keys ) {
	$windowsMachines[$ipTarget]
}
