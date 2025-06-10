# checklinuxmachines.ps1 version 1.2 05-May 2024

# required in order to pass by reference
$result = ""

$autocheckModulePath = Join-Path -Path "$PSSCriptRoot" -ChildPath "autocheckfunctions.psm1"
If ( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else { 
	Write-Output "PSSCriptRoot: $PSSCriptRoot Cannot find AutoCheckfunctions.psm1. Abort."
	Exit
}

#####################################################################################
##### Check Linux machines (PuTTY sessions, DNS, valid IP and SSH service, L1 and L2)
#####################################################################################

# requires vCenter connection so keeping local to main script
# Report card #31 Static IPs on Linux VMs
# Report card #47 PuTTY entry for all Linix VMs: no password prompt
# Report card #50 no PuTTY session for vPodRouter

# Get Layer 1 Linux and Other VMs
Write-Output "Checking L1 Linux: valid IP, DHCP, DNS, router and SSH service..."
$Layer1Linux = @{}
$linuxMachines = @{}
$lines = Get-Content -Path $layerOneInfo
Foreach ($line in $lines) {
	#Write-Host $line
	If ( $line -eq "" -Or $line -Like '#*' ) { Continue }
	$IPAddress = ''
	($name,$os,$ipf) = $line.Split(',')
	$name = $name.Replace(" ", "")  # remove spaces
	
	If ( $os -Like "*windows*" ) { Continue } # only check Linux machines here
	If ( $name -Like "*manager*" ) { Continue } # do not check the Manager (only holuser account is available)
	If ( $name -Like "*mainconsole*" ) { Continue } # do not check the Main Console
	If ( $name -Like "*stg*-01a*" ) { Continue } # do not check the FreeNAS storage appliance
	If ( $name -Like "*vpodrouter*" ) { Continue } # do not check the vpodrouter
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ( ($name -like '*vPodRouter*') -Or ($name -like '*pfrouter*') ) { # vPodRouterHOL is special
		$name = 'router'
		$ipAddress = '10.0.100.1'
	}
	If ( $ipAddress -eq $stgIP ) { Continue } # skip FreeNAS storage appliance
	If ( $ipAddress -eq $mgrIP ) { Continue } # skip the Manager VM
	If ( -Not $ipAddress ) { # if no IPAddress we cannot check further
		Write-Logs "FAIL" $name "L1 IP address" "No IP address for L1 Linux machine $name. Cannot check."
		Continue # nothing else can be done
	}
	If ( $Layer1Linux[$ipAddress] ) { Continue }  # duplicate entry so skip it
	
	($nameIP) = VerifyDnsNameIP  $name $ipAddress 'L1'
	#Write-Host " nameIP: $nameIP"
	If ( $nameIP -ne $null ) {
		($dnsName,$dnsIP) = $nameIP.Split(":")
	} Else {
		Write-Output "No DNS record for $name."
	}
	#If ( $dnsIP -eq "unknown" ) { Write-Host " nameIP: $nameIP" }
	
	$target = $name + "(" + $IPAddress + ")"
	$lm = New-Object -TypeName psobject
	$lm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$lm | Add-Member -MemberType NoteProperty -Name OS -Value ($os.Trim())
	$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$lm | Add-Member -MemberType NoteProperty -Name Layer -Value "1"
	
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L1 DHCP" "L1 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	# check for SSH service response
	Test-TcpPortOpen -Server $IPAddress -Port '22' -Result ([REF]$result)
	If( $result -ne "success" ) {
		Write-Logs "FAIL" $target "No SSH answer" "No SSH response on $IPAddress cannot perform checks requiring SSH"
		$ssh = $false
		Continue
		Write-Output "No SSH answer" "No SSH response on $IPAddress cannot perform checks requiring SSH"
	} Else {
		$ssh = $true
		Write-Logs "PASS" $target "SSH answer" "Received an SSH response on $IPAddress so Linux checks will be performed. Thanks!"
	}
	$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
	
	# ssh is active but does root ssh work?
	If ( $ssh ) {
		$quiet = remoteLinuxCmdLMC $IPAddress $linuxuser $linuxpassword "date"
		#Write-Host "IPAddress: $IPAddress LASTEXITCODE: $LASTEXITCODE"
		If ( $LASTEXITCODE -ne 0 ) {
			Write-Logs "FAIL" $target "Root ssh" "No SSH access as root on $IPAddress cannot perform checks. Please check manually."
			Continue # no more testing
		}
	}
	If ( $name -Like "*CB-*" ) { # Cloudbuilder is special
		$lm | Add-Member -MemberType NoteProperty -Name account -Value "admin"
	} Else {
		$lm | Add-Member -MemberType NoteProperty -Name account -Value "root"
	}
	
	#Write-Output "Adding $target to Layer1Linux hash."
	$Layer1Linux[$IPAddress] = $lm
	$linuxMachines[$IPAddress] = $lm
}

<#
# handy during dev for debugging
If ( Test-Path "layer1linux.csv" ) { Remove-Item -Path "layer1linux.csv" }
Foreach ( $ipTarget in $Layer1Linux.keys ) {
		$Layer1Linux[$ipTarget] | ConvertTo-CSV | Add-Content "layer1linux.csv"
}
#>

# End get L1 Linux machines

# 
# Get Layer 2 Linux and Other VMs
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

$Layer2Linux = @{}
If ( $vcPresent ) { 
	Write-Output "Checking L2 Linux: valid IP, DHCP, DNS and SSH service..."
	$allvms = Get-VM -ErrorAction SilentlyContinue
}

Foreach ($vm in $allvms) {
	$IPAddress = ""
	$name = $vm.Name
	If ( $name -Like "*vCLS-*" ) { Continue }
	If ( $name -Like "SupervisorControlPlaneVM*" ) { Continue}
	If ( $name -Like "edge*mgmt*" ) { Continue}
	If( $vm.GuestId -notmatch 'linux|ubuntu|debian|centos|sles|redhat|photon|rhel|other' ) { Continue }
	
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
	If ( -Not $nameIP ) { 
		Write-Output "Skipping $name.  nameIP: $nameIP"
		Continue 
	} # Nothing can be done.
	# 08/18/2020 added logic for L2 NAT
	($dnsName,$dnsIP,$vmIP) = $nameIP.Split(":")
	#Write-Host "dnsName: $dnsName dnsIP: $dnsIP vmIP: $vmIP"
	$tmpIP = $vmIP | Out-String
	$vmIP = $vmIP.Trim()
	$tmpIP = $dnsIP | Out-String
	$dnsIP = $vmIP.Trim()
	If ($dnsIP -ne $vmIP) { 
		Write-Output "$name is not in DNS or NAT detected. vmIP: $vmIP dnsIP: $dnsIP"
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
	$IPtmp = $IPAddress | Out-String
	$IPAddress = $IPtmp.Trim()
	$target = "${name}(${IPAddress})"
		
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	# 07/21/2021 test the connection to the IP and if none - remove the machine. FAIL
	# 09/03/2021 if PowerShell Test-Connection fails, try ping to be certain before skipping.
	#Write-Output "Checking network connectivity to $target..."
	$ok = $false
	If ( $psVersion -ge 6 ) { # current PowerShell support
		Try {
			$statusResults = Test-Connection -TargetName $IPAddress -Count 4
		} Catch {}
	} Else { # old versions (why using?)
		$statusResults = Test-Connection -ComputerName $IPAddress -Count 4
	}
	ForEach ($res in $statusResults) {
		If ( $res.Status -eq "Success" ) { $ok = $true }
	}
	If ( -Not $ok ) {
		Write-Output "PS test-connection to $target says no connectivity. Trying ping"
		$statusResults = Invoke-Expression "ping -c 4 $IPAddress"
		If ( $statusResults -NotLike "*timed out."  ) {
			Write-Output "Network connectivity ok to $target"
			$ok = $true
		} Else {
			$removeMachines += $IPAddress
			Write-Logs "FAIL" $target "Connection" "No network response at $IPAddress so cannot perform Linux checks. Please check this machine manually."
			Continue
		}
	} Else {
		Write-Output "Network connectivity ok to $target"
	}
	
	# check for SSH service response
	If ( $IPAddress ) {
		If ( $Layer2Linux[$IPAddress] ) { Continue } # seems like getting $allvms includes some duplicates
		Write-Output "Testing ssh to $target..."
		$sshCtr = 0
		Do {
			If ( $sshCtr -ge 2 ) {  # opportunity to use Invoke-VMScript
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
	If ( $name -Like "sddc-manager*" ) { $account = "vcf" 
	} Else { $account = "root" }
	$lm | Add-Member -MemberType NoteProperty -Name account -Value $account
	$lm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$lm | Add-Member -MemberType NoteProperty -Name OS -Value $vm.GuestId
	$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$lm | Add-Member -MemberType NoteProperty -Name Layer -Value "2"
	
	If ( $ssh ) {
		$quiet = remoteLinuxCmdLMC $IPAddress $linuxuser $linuxpassword "date"
		If ( $LASTEXITCODE -ne 0 ) {
			Write-Logs "FAIL" $target "Root ssh" "No SSH access as root on $IPAddress cannot perform checks. Please check manually."
			restorePowerState $name $lm.Off
			Continue # no more testing
		}
	}
	
	If ( $IPAddress ) {
		$Layer2Linux[$IPAddress] = $lm
		$linuxMachines[$IPAddress] = $lm
	}
	
	# if we powered it on, power it off before we figure out the next Linux L2 VM
	restorePowerState $name $lm.Off
} 

# Only handy during dev for debugging
#If ( Test-Path "layer2linux.csv" ) { Remove-Item -Path "layer2linux.csv" }
#Foreach ( $ipTarget in $Layer2Linux.keys ) {
#		$Layer2Linux[$ipTarget] | ConvertTo-CSV | Add-Content "layer2linux.csv"
#}

# End get L2 Linux machinesL2 Linux machines

# if WMC check PuTTY sessions
If ( $WMC ) {
	# read the output file and add the entries to $puttySessions
	Write-Output "WMC detected. Performing PuTTY session checks..."
	Copy-Item "/home/holuser/autocheck/puttysessions.ps1" "$mcholroot/run.ps1"
	$quiet = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	Remove-Item "$mcholroot/run.ps1"
	$puttySessions = Get-Content "$mcholroot/puttysessions.txt"
	
	# Check PuTTY entries
	Foreach ($session in $puttySessions) {
		Write-Output "Checking PuTTY $session..."
		$puttyIP = ""
		$puttyHost = ""
		$target = ""
		$puttyFields = $session.Split('~')
		$hostName = $puttyFields[0]
		$puttyUserName = $puttyFields[1]

		If ( $session -Like '*Default*') { Continue }	# skip Default
	
		If ( $hostName -Like '*@*' ) { 
			($puttyUserName, $puttyHost) = $hostName.Split('@') # if $account - correct HOL convention
		} Else {		
			$puttyHost = $hostName
		}
	
		If ( $puttyHost -Match $IPRegex ) { # is it an IP?
			$puttyIP = $puttyHost
		}
		If ( ($puttyHost -NotLike "*.$dom") -Or !($puttyHost -NotLike "*.vcf2*" ) ) { $puttyHost = $puttyHost + ".$dom" }
		#Write-Host "python3 nameip.py $puttyHost"
		$output = Invoke-Expression "python3 nameip.py $puttyHost"
		#Write-Host  "nameip output: $output"
		<#$ctr = 0
		ForEach ( $line in $output ) {
			Write-Host "$ctr $line"
			$ctr++
		} #>
		($dnsNameTmp, $dnsIP, $puttyIP) = $output.Split(":")
		#Write-Host "$dnsNameTmp, $dnsIP, $puttyIP"
		$target = "${puttyHost}(${puttyIP})"
		If ( $puttyIP -eq "unknown" ) {
			Write-Logs "INFO" $target "PuTTY Session" "DNS lookup failed for ${puttyHost}. Perhaps this PuTTY session should be deleted."
		}
		If ( $puttyIP -like "10.0.*.1" ) { # don't want a PuTTY session for the router in most cases
			Write-Logs "FAIL" $target "PuTTY Convention" "HOL does not want a PuTTY session to the vPodRouter. Please delete unless an exception is granted."
			Continue
		}
		If ( $puttyIP -like "10.0.*.11" ) { # don't want a PuTTY session for the manager in most cases
			Write-Logs "FAIL" $target "PuTTY Convention" "HOL does not want a PuTTY session to the Manager. Please delete unless an exception is granted."
			Continue
		}
		$found = $false
		ForEach ( $ip in $linuxMachines.keys ) {
			If ( $puttyIP -eq $ip ) { 
				$found = $true
				Break
			}
		}
		#Write-Host "puttyIP: $puttyIP linuxMachines[$puttyIP].dnsName: $dnsName" 
		If ( $found ) { # found it
			# take note that this Linux machine has a PuTTY session
			$linuxMachines[$ip] | Add-Member -MemberType NoteProperty -Name PuTTY -Value $true -Force
			If ( $puttyUserName ) {
				# pass and following HOL convention
				Write-Logs "PASS" $target "PuTTY Convention" "PuTTy session ${puttyHost} uses proper HOL convention account@host."
			} ElseIf ( $puttyUserName ) {
				# pass but not HOL convention
				Write-Logs "INFO" $target "PuTTY Convention" "PuTTy session ${puttyHost} does NOT use the proper HOL convention account@host but does specify ${puttyUserName} as default."
			} Else {
				# INFO no account specified
				Write-Logs "INFO" $target "PuTTY Convention" "PuTTy session ${puttyHost} does NOT use the proper HOL convention account@host and no account name is specified."
			}
			# compare the name used in $lnuxMachines to $puttyHost
			If ( $puttyHost -ne $linuxMachines[$ip].name ) {
				$lmName = $linuxMachines[$ip].name
				If ( $puttyHost -ne "$lmName.$dom" ) {
					Write-Logs "INFO" $target "PuTTY Conventions" "PuTTY session ${puttyHost} uses ${puttyHost} instead of ${lmName}."
				}
			}
		} Else {
			# This could be a stand alone L2 VM on ESXi or possibly on another hypervisor (KVM or Hyper-V)
			# check for SSH service response
			Test-TcpPortOpen -Server $puttyIP -Port '22' -Result ([REF]$result)
			If( $result -ne "success" ) {
				Write-Logs "INFO" $target "PuTTY Session" "No ssh response for ${hostName}. Perhaps this PuTTY session should be deleted?"
			} ElseIf ( $puttyIP -ne "unknown") {
				$ssh = $true
				Write-Logs "PASS" $target "SSH answer" "Received an SSH response on $puttyIP so Linux checks will be attempted. Thanks!"
				# check DNS
				If ( $hostName -eq "" ) { Continue }
				If ( $hostName -Like "*@*" ) { ($junk, $hostName) = $hostName.Split('@') }
				#Write-Host "hostName: $hostName puttyIP: $puttyIP"
				($nameIP) = VerifyDnsNameIP  $hostName $puttyIP 'L2'
				($dnsName,$dns,$junk) = $nameIP.Split(":")
				#Write-Host "dnsName: $dnsName dnsIP: $dns"
				If ( $dns -eq $null ) {
					Write-Output "No DNS record for $name."
					$dnsIP = "unknown"
				}
				# add this machine to the list for checking
				$lm = New-Object -TypeName psobject
				$lm | Add-Member -MemberType NoteProperty -Name Name -Value $hostName
				$lm | Add-Member -MemberType NoteProperty -Name OS -Value "Linux" # don't really know at this point
				$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
				$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $puttyIP
				$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
				$lm | Add-Member -MemberType NoteProperty -Name Layer -Value "unknown"
				# I don't think we need this - never do anything with it
				#$lm | Add-Member -MemberType NoteProperty -Name sshRoot -Value "unknown"
				$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
				$lm | Add-Member -MemberType NoteProperty -Name account -Value $puttyUserName
				$lm | Add-Member -MemberType NoteProperty -Name PuTTY -Value $true -Force
				$Layer2Linux[$puttyIP] = $lm
				$linuxMachines[$puttyIP] = $lm
			}
		}
		#$linuxMachines[$puttyIP] | Add-Member -MemberType NoteProperty -Name PuTTY -Value $false -Force
		#Write-Output "sessionName: $puttyHost puttyIP: $puttyIP"
	}# End Foreach PuTTY sessions

	# Does every Linux machine (except the router) have a PuTTY session?
	$ips = ""
	Foreach ( $ipTarget in $linuxMachines.keys ) {
		If ( $ips.Contains($ipTarget) ) { Continue } # no duplicates	
		#$hostName = $linuxMachines[$ipTarget].dnsName	
		$hostName = $linuxMachines[$ipTarget].Name
		#Write-Host "hostName: $hostName ipTarget: $ipTarget"
		If ( $ipTarget -eq $mcIP ) { Continue }
		If ( $ipTarget -Like "10.0.*.1" ) { Continue }
		If (-Not $linuxMachines[$ipTarget].PuTTY ) {		
			#Write-Host "no PuTTY"
			$target = $hostName + "(" + $ipTarget + ")"
			Write-Logs "INFO" $target "PuTTY Entry" "No PuTTY entry for $target."
		}
		$ips = $ips + $ipTarget	
	}
} # End check PuTTY sessions if WMC

<#
# handy for debugging and testing
If ( Test-Path "layer2linux.csv" ) { Remove-Item -Path "layer2linux.csv" }
Foreach ( $ipTarget in $Layer2Linux.keys ) {
		$Layer2Linux[$ipTarget] | ConvertTo-CSV | Add-Content "layer2linux.csv"
}
#>

##############################################################################
#####  BEGIN LINUX CHECKS LAYER ONE AND LAYER TWO
#####
#####    ssh access, kernel type, NTP, time delta, ssh auth, 
#####    password aging and EXT FS checks disabled
##############################################################################

# creates/updates $linuxMachines hash of PowerShell custom objects so local to main script
# could access L2 via Invoke-VMScript no ssh but needs vCenter connetions

Write-Output "Checking Linux ssh access, kernel type, NTP, time delta, ssh auth, password aging and EXT FS checks disabled..."


# Before we get started on Linux checks, verify ntpd is running on the vPodRouterHOL.
$ntpdOK = $false
$ntpdTest = @"
"ps -ef | grep ntpd | grep -v grep"
"@

Try {
	$output = remoteLinuxCmdLMC "router.$dom" $linuxuser $linuxpassword $ntpdTest
	If ( $output -NotLike "*/usr/sbin/ntpd*" ) { $output = "BAD" }
	#Write-Output "$output"
	If ( $output -ne "BAD" ) { $ntpdOK = $true }
} Catch {
	Write-Output "Cannot check ntpd status on router.$dom."
	$ntpdOK = $false
}

If ( $output -eq "BAD" ) {
	Try {
		Write-Output "Starting ntpd on router.$dom..."
		$ntpdRestart = "systemctl restart ntp.service"
		$raw = remoteLinuxCmdLMC "router.$dom" $linuxuser $linuxpassword $ntpdRestart			
		If ( -Not ($raw) ) { $output = $true }
		Else { $output = $false }
		If ( $output ) { $ntpdOK = $true }
	} Catch {
		Write-Output "Cannot start ntpd on router.$dom."
		$ntpdOK = $false
	}
}

If ( $ntpdOK ) {
	Write-Output "NTPD is running on the HOL router. Time checks will be done."
} Else {
	Write-Output "NTPD is NOT runnning on the HOL Router. NTPD could not be started. Skipping time checks."
}

# copy the ssh auth script to the WMC
If ( $WMC ) { Copy-Item $PSSCriptRoot/wmcauth.ps1 $mcholroot/wmcauth.ps1 }

$removeMachines = @()
$max = 5
Foreach ($ipTarget in $linuxMachines.keys) {  # BEGIN main loop for all Linux checks L1 and L2

	$errorVar = $null
	$ctr = 0
	$name = $linuxMachines[$ipTarget].name
	$hostName = $linuxMachines[$ipTarget].dnsName
	If ( $hostName -ne $name ) { $hostName = $name } # Use the Name if not in DNS
	$account = $linuxMachines[$ipTarget].account
	$target = $hostName + "(" + $ipTarget + ")"
	$os = $linuxMachines[$ipTarget].OS
	
	If ( $linuxMachines[$ipTarget].ssh -eq $false  ) { # nothing we can do.
		If ( $removeMachines[$ipTarget] ) { Continue } # duplicates here for some reason
		Write-Output "Skipping $target because no ssh access."
		$removeMachines += $ipTarget
		Continue 
	}
	
	Write-Output "Attempting Linux checks on $target..."

	If ( $linuxMachines[$ipTarget].Layer -eq "2" ) { $vm = Get-VM -Name $name }

	# Power on L2 Linux machine for checks then power off when complete
	If ($linuxMachines[$ipTarget].Off) { # this has to be a Layer 2 machine
		# power on, check SSH then update $linuxMachines[$ipTarget].ssh
		Write-Output "Powering on L2 Linux VM $hostName to perform Linux checks..."
		$result = start-L2 $name
		$snap = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
		$sshCtr = 0
		Do {
			If ( $sshCtr -ge 5 ) {  # opportunity to use Invoke-VMScript
				$linuxMachines[$ipTarget].ssh = $false
				Write-Logs "FAIL" $target "SSH answer" "No SSH response on L2 $ipTarget after power on. Please check manually."
				Write-Output "Powering off L2 machine $hostName since no ssh response after power on..."
				$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false
				$removeMachines += $ipTarget
				Break
			}
			Test-TcpPortOpen -Server $ipTarget -Port '22' -Result ([REF]$result)
			If( $result -eq "success" ) {
				$linuxMachines[$ipTarget].ssh = $true
				Write-Logs "PASS" $target "SSH answer" "Received SSH response on L2 $target after power on. Thanks!"
				Break
			} 
			Start-Sleep $sleepSeconds
			$sshCtr++
		} While ( $result -ne "success" )
	}
	If ( ($hostName -Like "*infoblox*") -Or ($hostName -Like "*panorama*") ) { # this list may grow.
		Write-Logs "INFO" $target "root ssh" "Cannot check $hostName. Please check manually as needed."
		$removeMachines += $ipTarget
		Continue
	}
	#Write-Output "hostName: $hostName ipTarget: $ipTarget nsxV: $nsxV nsxT: $nsxT"
	If ( ($hostName -Like "*nsx*") -Or ($hostName -Like "*csm*") -Or ($hostName -Like "*edge*") ) { # counting on this naming convention (need to do IP address checking
		Write-Output "Attempting to check NSX accounts for password expiration and license status on $target..."
		Invoke-Expression "python3 $PSSCriptRoot/checknsx.py `"$hostName`" $ipTarget > /tmp/output.txt"
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
		$removeMachines += $ipTarget
		Continue # nothing more to do with this one
	}
	
	# Check Linux type with uname -a (need to identify special exceptions)
	If ( $hostName -Like "*vcenter*" ) { 
		$output = "photon"
	} Else {
		Write-Output "Getting uname on $target ..."
		$unameCmd = "uname -a"
		$output = remoteLinuxCmdLMC $iptarget $linuxuser $password $unameCmd
		$output = $output.Trim()
	}
	If ( $output -Like "*DENIED*" ) {
		Write-Logs "FAIL" $target "$account ssh" "Cannot ssh as $account on $hostName. Bad ssh configuration or bad $account password. No further checks possible. Please perform Linux checks manually."
		$linuxMachines[$ipTarget].ssh = $false
		If ($linuxMachines[$ipTarget].off) { 
			$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false 
		}
		Continue
	} Else {
		#Write-Output "$hostName uname: $output"
		If ( $output -Like "*photon*"  ) { $output = "photon" }
		$linuxMachines[$ipTarget] | Add-Member -MemberType NoteProperty -Name uname -Value $output
	}
	
	#27 All VMware products licensed and will not expire before $licenseExpireDate
	#66 vCloud Director storage leases never expire
	# check for VMware Appliance
	If ( $hostName -Like "*esx*" ) {
		$vmApplianceCheck = $false # this is not the VMware appliance you seek
	} Else {
		$vmApplianceCheck = $false
		$checkCmd = @"
"test -d /opt/vmware && echo True || echo False"
"@
		$errorVar = $null
		$output = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $checkCmd
	
		If ( $errorVar -Or $LASTEXITCODE ) {
			Write-Logs "FAIL" $target "Appliance check" "Cannot check if VMware Appliance on $hostName $errorVar"
			$vmApplianceCheck = $false
		}
		If ($output -Like "*True*" ) { # VMware Appliance now check product license expirations
			$vmApplianceCheck = $true
			#Write-Output "Found VMware Appliance $target"
		}
		#Write-Output "vmApplianceCheck: $hostName $ipTarget $vmApplianceCheck"
	}
	
	If ( $vmApplianceCheck ) {
		# check vRA license
		$checkCmd = @"
"test -f /usr/local/bin/vracli && echo True || echo False"
"@
		$ouput = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $checkCmd		

		If ( $output -Like "*True*" -And ($hostName -Like "vra*" -Or $hostName -Like "*vr-automation*") ) { 
			Write-Output "Checking for vRA license on $hostName..."
			$vmAppliance = $false # found vRA appliance so switch off the flag
			$nf = '$NF' # getting the dollar sign across is tricky
			$vraCmd = @"
"vracli license | grep -i automation | awk '{print $nf}'"
"@
			Try {
				Write-Logs "WARN" $target "vRA Checks" "vRA checking using LMC is NOT verified. Please check manually."
				$output = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $vraCmd
				# TODO: need to verify the output and Get-Date works correctly
				If ( $output ) { 
					$vraExpireDate = Get-Date "$output 12:00:00 AM"
				} ElseIf ( $hostName -Like "*vro*" ) {
					Write-Logs "INFO" $target "vRO License" "Please manually verify that vRO is NOT using a 90-day evaluation license."
				} Else {
					Write-Logs "FAIL" $target "vRA License" "Cannot check vRA license on $hostName. Is the appliance working correctly?"
				}
				If( $vraExpireDate -and (($vraExpireDate -ge $chkDateMin) -and ($vraExpireDate -le $chkDateMax)) ) {
					Write-Logs "PASS" $target "vRA License" "vRA license on $hostName is good and expires $vraExpireDate"
				} ElseIf ( $vraExpireDate ) {
					Write-Logs "FAIL" $target "vRA License" "vRA license on $hostName is bad and expires $vraExpireDate"
				}
			} Catch {
				If ( $hostName -Like "*vro*" ) { # 11/30/2020 standalone vRO appliance
					Write-Logs "INFO" $target "vRO License" "Please manually verify that vRO is NOT using 90-day evaluation license."
				} Else {
					Write-Logs "FAIL" $target "vRA License" "Cannot check vRA license on $hostName. Is the appliance working correctly?"
				}
			}
		} # End check vRA license
		
		# check for Cloud Director appliance using DNS hostName for REST calls
		If ( $vmApplianceCheck -And $linuxMachines[$ipTarget].dnsIP ) {			
			$checkCmd = @"
"test -f  /opt/vmware/vcloud-director/bin/vmware-vcd-cell && echo True || echo False"
"@
			$output = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $checkCmd
			# TODO: need to verify output for VCD
			If ( $output -Like "*True*" ) {
				$vmAppliance = $false # found vCD appliance so switch off the flag
				Write-Output "Attempting to check Cloud Director license and storage lease expirations..."
				$checkVCD = Join-Path $PSScriptRoot -ChildPath "checkvcd.ps1"
				$vcdLog = Join-Path -Path $logDir -ChildPath "vCDcheck.log"
				$vcdErr = Join-Path -Path $logDir -ChildPath "vCDcheck.err"
				# must be started in a separate PowerShell process
				Start-Process $powerShell -ArgumentList "-command $checkVCD $hostName $ipTarget"  -Wait -RedirectStandardOutput $vcdLog -RedirectStandardError $vcdErr
			}
		} # End check for vCloud Director appliance using DNS hostName for REST calls
		
		# check for vRealize Operations appliance using DNS hostName for REST calls
		If ( $vmApplianceCheck -And $linuxMachines[$ipTarget].dnsIP ) {			
			$checkCmd = @"
"test -f  /opt/vmware/bin/vrops-status && echo True || echo False"
"@
			$output = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $checkCmd
			# TODO: need to verify output
			If ( $output -Like "*True*" ) {
				$vmAppliance = $false # found vROPs appliance so switch off the flag
				Write-Output "Attempting to check vRealize Operations license..."
				$checkvROPs = Join-Path -Path $PSScriptRoot -ChildPath "checkvrops.ps1"
				Invoke-Expression "$checkvROPs $hostName $ipTarget $apiVersion"
			}
		} # End check for vRealize Operations appliance using DNS hostName for REST calls
		
	} # End VMware Appliance check
	
	If ( $linuxMachines[$ipTarget].ssh -eq $false ) {
		$removeMachines += $ipTarget
		If ($linuxMachines[$ipTarget].off) { 
			$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false 
		}
		Continue
	}

	##############################################################################
	##### Check Linux time ( use account and VMware123! password )
	##### Report card #52 VMs syncd to ntp.vcf.sddc.lab or 10.0.100.1
	##############################################################################	
	Write-Output "Checking Linux NTP configuration and time difference on $target ..."
	
	If ( ($hostName -like 'esx*') -Or ($hostName -like '*nsx*') -Or ($hostName -like '*router*') ) {
		Write-Logs "PASS" $hostName "NTP" "Skipping time checks on $hostName"		
	} Else {
	
		$uname = $linuxMachines[$ipTarget].uname
		$uname = "`"$uname`"" # need to escape the quotes to pass as a single argument
		$timeCheck = Join-Path $PSScriptRoot -ChildPath "checklinuxtime.ps1"
		If ( $ntpdOK ) {
			# getting a weird error here.
			#The Unicode escape sequence is not valid. A valid sequence is `u{
			# | followed by one to six hex digits and a closing '}'.
			Invoke-Expression "$timeCheck `"$hostName`" $ipTarget $uname $account"
		}
	}

	#### END Linux time check
	
	##############################################################################
	##### Check SSH auth (no password required)
	##### Update $linuxMachines array hash so keeping local to main script
	##### Report card #48 SSH AUTH for passwordless login
	##############################################################################
	
	If ( $ipTarget -eq $mcIP ) { Continue } # no sense checking this on the MC
	
	Write-Output "Checking SSH Auth using public key on $target ..."

	If ( $WMC ) {
		$output = RunWinCmd "pwsh -File C:\hol\wmcauth.ps1 $ipTarget root" ([REF]$result) 'mainconsole' 'Administrator' $password
		If ( $output -Like "*BAD*" ) { $errorVar = $output }
	} ElseIf ( $LMC ) {
		$errorVar = $null
		# if using a bogus password works then ssh auth is enbabled.
		$raw = testsshauthLMC $ipTarget $linuxuser "bogus" "date"
		If ( $raw -Like "*sshauth: FALSE" ) { $errorVar = "FAIL" }
	}
	If ( $errorVar -ne $null ) {
		$linuxMachines[$ipTarget] | Add-Member -MemberType NoteProperty -Name sshAuth -Value $false
		If ($ipTarget -like '*.*.*.1') { # vPodRouter is special case - don't want SSH Auth
			Write-Logs "PASS" $target "root SSH Auth" "SSH Auth is NOT configured for root on $hostName"
		} Else {
			Write-Logs "WARN" $target "root SSH Auth" "SSH Auth is NOT configured for root on $hostName"
		}
	} Else {
		$linuxMachines[$ipTarget] | Add-Member -MemberType NoteProperty -Name sshAuth -Value $true
		If ($ipTarget -like '*.*.*.1') { # vPodRouter is special case - don't want SSH Auth
			Write-Logs "FAIL" $target "root SSH Auth" "SSH Auth must NOT be configured for root on $hostName"
		} Else {
			Write-Logs "PASS" $target "root SSH Auth" "SSH Auth for root is configured on $hostName Thanks!"
		}
	}
	If ( $account -ne "root" ) { # if alternate account, check for SSH Auth as well
		If ( $WMC ) {
			$output = RunWinCmd "pwsh -File C:\hol\wmcauth.ps1 $ipTarget $account" ([REF]$result) 'mainconsole' 'Administrator' $password
			If ( $output -Like "*BAD*" ) { $errorVar = $output }
		} ElseIf ( $LMC ) {
			$errorVar = $null
			# if using bogus password works then ssh auth is enbabled.
			$raw = testsshauthLMC $ipTarget $account "bogus" "ls"
			If ( $LASTEXITCODE -ne 0 ) { $errorVar = "FAIL" }
		}
		If ( $errorVar ) {
			$linuxMachines[$ipTarget].sshAuth = $false
			Write-Logs "WARN" $target "$account SSH Auth" "SSH Auth is NOT configured for $account on $hostName"
		} Else {
			$linuxMachines[$ipTarget].sshAuth = $true
			Write-Logs "PASS" $target "$account SSH Auth" "SSH Auth for $account is configured on $hostName Thanks!"
		}
	}
	#### END Check SSH auth (no password required)

	#30 No SLES or RedHat VMs (unless VMware appliances)
	$redHatSUSEscript = Join-Path -Path $PSScriptRoot -ChildPath "checklinuxrh-suse.ps1"
	If ( $os -Like "*SUSE*" -Or $os -Like "*CentOS*" -Or $os -Like "*Red*Hat*" ) {
		Invoke-Expression "$redHatSUSEscript `"$hostName`" $ipTarget `"$os`""
	}
	
	##############################################################################
	##### Check Linux Password expiration
	##### Report card #46 passwords set to NEVER expire
	##############################################################################
	Write-Output "Checking Linux password expiration on $target ..."

	# TODO: check all accounts or just root? - just root for now
	# NSX and ESX machines are different - no chage

	If ($linuxMachines[$ipTarget].uname -match "tinycore" ) { # chage not found exceptions
		Write-Logs "PASS" $target "root password aging" "Skipping root password check on $hostName since no chage command"

		if (-not ([string]::IsNullOrEmpty($linuxMachines[$ipTarget].Off))) {
			restorePowerState $name $linuxMachines[$ipTarget].Off
			Continue
		}
	}
	If ($linuxMachines[$ipTarget].uname -like "*FreeBSD*" ) { # chage not found exceptions
		# if really wanted to...
		# FreeBSD: "pw showuser root | cut -d: -f 6" returned value should be "0"
		Write-Logs "PASS" $target "root password aging" "Skipping root password check on $hostName since no chage command"
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off }
		Continue
	}
	If ( ($hostName -like '*esx*') -Or ($hostName -like '*nsx*') ) {
		Write-Logs "PASS" $target "root password aging" "Skipping root password aging on $hostName" # unlikely but could be a L2 ESXi host
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off }
		Continue
	}
	If (-Not $linuxMachines[$ipTarget].ssh) { # opportunity to check using Ivoke-VMScript if L2
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off}
		Continue
	}
	# call external script here
	$clpScript = Join-Path -Path $PSScriptRoot -ChildPath "checklinuxpass.ps1"
	Invoke-Expression "$clpScript `"$hostName`" $ipTarget $account"

	#### End Check Linux Password expiration
	
	##############################################################################
	##### Check Linux EXT file systems
	##### Report card #33 Disable fsck of ext file systems
	##############################################################################
	Write-Output "Checking Linux EXT file systems (verify fsck is disabled) on $target ..."
	
	If ($linuxMachines[$ipTarget].uname -like '*tinycore*' ) { # dump2fs not found exceptions
		Write-Logs "PASS" $target "EXT FS" "Skipping EXT FS check on $hostName since no dump2fs command"
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off }
		Continue
	}	If ($linuxMachines[$ipTarget].uname -like '*FreeBSD*' ) { # dump2fs not found exceptions
		Write-Logs "PASS" $target "EXT FS" "Skipping EXT FS check on $hostName since no dump2fs command"
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off }
		Continue
	}
	If ( ($hostName -like 'esx*') -Or ($hostName -like '*nsx*') ) {
		Write-Logs "PASS" $target "EXT FS" "Skipping EXT FS check on $hostName"
		If ($linuxMachines[$ipTarget].off) { restorePowerState $name $linuxMachines[$ipTarget].Off }
		Continue
	} 
	
	# call external script here
	$clEXTFS = Join-Path $PSScriptRoot -ChildPath "checklinuxextfs.ps1"
	Invoke-Expression "$clEXTFS `"$hostName`" $ipTarget"
	
	#### End Check Linux EXT file systems
	
	# if we powered on the machine, power it off
	If ($linuxMachines[$ipTarget].Off) { 
		Write-Output "End of Linux checks for $hostName. Powering off $hostName..."
		restorePowerState $name $linuxMachines[$ipTarget].Off
	}

} # END Linux checks loop

# DEBUG
If ( Test-Path "layer1linux.csv" ) { Remove-Item -Path "layer1linux.csv" }
Foreach ( $ipTarget in $Layer1Linux.keys ) {
		$Layer1Linux[$ipTarget] | ConvertTo-CSV | Add-Content "layer1linux.csv"
}

# DEBUG
If ( Test-Path "layer2linux.csv" ) { Remove-Item -Path "layer2linux.csv" }
Foreach ( $ipTarget in $Layer2Linux.keys ) {
		$Layer2Linux[$ipTarget] | ConvertTo-CSV | Add-Content "layer2linux.csv"
}

# DEBUG
If ( Test-Path "linuxmachines.csv" ) { Remove-Item -Path "linuxmachines.csv" }
Foreach ( $ipTarget in $linuxMachines.keys ) {
		$linuxMachines[$ipTarget] | ConvertTo-CSV | Add-Content "linuxmachines.csv"
}

endAutoCheck
