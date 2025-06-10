# checkvsphere.ps1 version 1.4 30-May 2025

# required in order to pass by reference
$result = ""

$autocheckModulePath = Join-Path -Path "$PSSCriptRoot" -ChildPath "autocheckfunctions.psm1"
If ( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else { 
	Write-Output "PSSCriptRoot: $PSSCriptRoot Cannot find AutoCheckfunctions.psm1. Abort."
	Exit
}
# Report card #12 vCenters reachable
#FQDN(s) of vCenter server(s): also from VCENTERS file in C:\HOL\Resources
Set-Variable -Name "vCenters" -Value $(Read-ConfigIntoArray "RESOURCES" "vCenters")
If ( $vCenters ) { Write-Output "Checking vCenter connections..." }
$vcsToTest = @()
$vcPresent = $false
Foreach ($entry in $vCenters) {
	$login = ""
	($vcserver,$type,$login) = $entry.Split(":")
	If ( $login ) { $vcusers = ,$login + $vcusers } # use the login field first if present
	$vcsToTest += $vc
	$ctr = 1
	Foreach ($vcuser in $vcusers) {
		Write-Host "Connect-VC $vcserver $vcuser $password"
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

##############################################################################
##### Check FreeNAS iSCSI datastores against Datastores.txt
##############################################################################
# Robust lab startup scripts (Are FreeNAS iSCSI datastores in config.ini?)

If ( $vcPresent ) { Write-Output "Verifying FreeNAS VMFS datastores are checked by LabStartup..." }

Set-Variable -Name "Datastores" -Value $(Read-ConfigIntoArray "RESOURCES" "Datastores")
Foreach ( $line in $datastores ) {
	($s,$d) = $line.Split(":")
	$dsNames += $d
}

If ( $vcPresent ) { $vcDS = Get-Datastore | Where {$_.Type -eq "VMFS"} }
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

# Begin legacy vPodChecker code

##############################################################################
##### Check vESXi NTP Settings
##############################################################################
# Report Card #15 NTP configured on ESXi hosts

# this will also identify stand-alone ESXi hosts
Set-Variable -Name "ESXIHOSTS" -Value $(Read-ConfigIntoArray "RESOURCES" "ESXIHOSTS")

If ( $vcPresent ) { 
	Write-Output "Checking vESXi NTP configuration..."
	$allhosts = Get-VMHost -ErrorAction SilentlyContinue
}

##### NTP is configured
$function = "vESXi NTP"
Foreach ($h in $allhosts) {
	If ( $h.model -eq "VMware Mobility Platform" ) { Continue } # skipping the "ghost" ESXi hosts that HCX uses
	$ntpRunning = ""
	$ntpPolicy = ""
	$ntpServer = ""
	$ntpData = Get-VMHostService -VMHost $h	| where { $_.key -eq 'ntpd' }
	If ( $ntpData ) {
		$ntpRunning =	$ntpData.Running
		$ntpPolicy	=	$ntpData.Policy
		$ntpServer	 =	Get-VMHostNtpServer -VMHost $h
		$output = "NTP running: " + $ntpRunning + " NTP Policy: " + $ntpPolicy + " NTP Server: " + $ntpServer
		$result = Choose-TimeSource $ntpServer
		If ( $ntpRunning -and $result -ne "invalid" ) {
			Write-Logs "PASS" $h.name $function $output
		} Else {
			Write-Logs "FAIL" $h.name $function $output
		}
	} Else {
		Write-Logs "FAIL" $h.Name $function "NTP is not configured on $h"
	}

} # End Check vESXi NTP Settings

#4 vPod was created from approved templates
##### check vCenter version and build numbers

# need to maintain vcVersion and build number hash from the base templates
$vcVersion = @{"24700475" = "9.0.0"} # 2025 VCF base RTM1
$vcVersion.Add("24734770", "9.0.0")  # 2025 VCF base GOLD

$function = "vCenter build"
If ( $vcPresent ) { 
	Write-Output "Checking vSphere version/build configuration..."
	ForEach ( $s in $global:DefaultVIServers ) {
		$name = $s.name
		$version = $s.Version
		$build = $s.Build
		If ( ( $vcVersion[$build] -eq $version ) -Or ( $vcVersion[$build] -eq "${version}VCF") ) {
			Write-Logs "PASS" $name $function "$name is running vCenter $version build $build which is a standard HOL build."
		} Else {
			Write-Logs "WARN" $name $function "$name is running vCenter $version build $build which is not a standard HOL build."
		}
	} 	
	$allhosts = Get-VMHost -ErrorAction SilentlyContinue
} # end vCenter version and build numbers


# need to maintain esxVersion and build number hash from the base templates
$esxVersion = @{"24700913" = "9.0.0"} # 2025 VCF base RTM1
$esxVersion.Add("24734766", "9.0.0")  # 2025 VCF base GOLD

##### check vESXi version and build numbers
$function = "vESXi Build"
$prevBuild = ""
Foreach ($h in $allhosts) {
	If ( $h.model -eq "VMware Mobility Platform" ) { Continue } # skipping the "ghost" ESXi hosts that HCX uses
	$version = $h.version
	$build = $h.build
	#Write-Output "$h version: $version build: $build"
	If ( ( $build -ne $prevBuild ) -And ( $prevBuild -ne "" ) ) {
		$diffBuilds = $true
	}
	#Write-Host "build: $build " $esxVersion[$version] $esxVersion["${version}VCF"]
	If ( ( $esxVersion[$build] -eq $version) -Or ( $esxVersion[$build] -eq "${version}VCF") ) {
		Write-Logs "PASS" $h.name $function "$h is running ESXi $version build $build which is a standard HOL build."
	} Else {
		Write-Logs "WARN" $h.name $function "$h is running ESXi $version build $build which is not a standard HOL build."
	}
	$prevBuild = $build
}

If ( $diffBuilds ) {
		Write-Logs "WARN" $h.name $function "ESXi hosts are running different builds. There might be vMotion compatibility issues."
} # End Check vESXi version and build

##############################################################################
##### Check Layer 2 VM UUID and Typematic Settings
##############################################################################

#Report Card #16 L2 VMs uuid.action = keep
#Report Card #17 L2 Linux TypeDelay

If ( $vcPresent ) {
	Write-Output "Checking Layer 2 VM UUID and Typematic Settings..."
	$allVMs = Get-VM -ErrorAction SilentlyContinue
}
$uuidFunction = "L2 VM uuid.action"
$typeFunction = "L2 Linux VM keyboard.typematicMinDelay"
$autolockFunction = "L2 Windows VM tools.guest.desktop.autolock"

##### Report UUID.action setting on vVMs
Foreach ($vm in $allVMs) {
	
	$vmName = $vm.Name
	If ( $vmName -Like "vCLS*" ) { Continue }
	If ( $vmName -Like "SupervisorControlPlaneVM*" ) { Continue }
	$currentUuidAction = Get-AdvancedSetting -en $vm -name uuid.action -ErrorAction SilentlyContinue
	$currentUuidActionValue = $currentUuidAction.Value
	If( $currentUuidActionValue -eq "keep" ) {
		Write-Logs "PASS" $vm.name $uuidFunction "The uuid.action VM property is set correctly on this Layer 2 VM. Thanks!"
	} ElseIf(! $currentUuidActionValue ) { 
		Try { # attempt to create uuid.action and if fail - probably NSX so INFO instead of FAIL
			New-AdvancedSetting -en $vm -name uuid.action -value 'keep' -Confirm:$false -ErrorAction 1 | Out-Null
			Write-Logs "FAIL" $vmName $uuidFunction "The uuid.action VM property is not present on $vmName Layer 2 VM. This can cause a VM question to interrupt start on dissimilar clouds."
		} Catch {
			Write-Logs "INFO" $vmName $uuidFunction "Unable to create the uuid.action VM property on $vmName which is probably a solution-managed Layer 2 VM."
		}
	} Else {
		Write-Logs "INFO" $vmName $uuidFunction "The uuid.action VM property is set to $currentUuidActionValue on L2 $vmName. Hopefully this will be alright in different clouds."
	}
	
	##### Report typematic delay... for Linux machines only	
	If( $vm.GuestId -match 'linux|ubuntu|debian|centos|sles|redhat|photon|rhel|other' ) {
		$currentTypeDelay = Get-AdvancedSetting -en $vm -name keyboard.typematicMinDelay -ErrorAction SilentlyContinue
		$currentTypeDelayValue = $currentTypeDelay.Value
		If( $currentTypeDelayValue -eq 2000000 ) {
			Write-Logs "PASS" $vmName $typeFunction "The keyboard.typematicMinDelay VM property is set correctly on $vmName Layer 2 VM. Thanks!"
		} ElseIf(! $currentTypeDelay ) {
			Try { # attempt to create and if fail - probably NSX so INFO instead of FAIL
				New-AdvancedSetting -en $vm -name keyboard.typematicMinDelay -value 2000000 -Confirm:$false -ErrorAction 1 | Out-Null
				Write-Logs "FAIL" $vmName $typeFunction "The keyboard.typematicMinDelay VM property is not set on $vmName Layer 2 VM. This can result in erratic keyboard entry in the VM console."
			} Catch {
				Write-Logs "INFO" $vmName $typeFunction "Unable to create the keyboard.typematicMinDelay VM property on $vmName which is probably a solution-managed Layer 2 VM."
			}
			
		} Else {
		Write-Logs "INFO" $vmName $typeFunction "The keyboard.typematicMinDelay VM property is set to $currentTypeDelayValue on L2 $vmName."
		}
	}
	
	##### Report autolock setting... for Windows machines only	
	If( $vm.GuestId -match 'windows' ) {
		$currentAutoLock = Get-AdvancedSetting -en $vm -name tools.guest.desktop.autolock -ErrorAction SilentlyContinue
		$currentAutoLockValue = $currentAutoLock.Value
		If( $currentAutoLockValue -eq 'FALSE' ) {
			Write-Logs "PASS" $vmName $autolockFunction "The tools.guest.desktop.autolock VM property is set correctly on $vmName Layer 2 VM. Thanks!"
		} ElseIf(! $currentTypeDelay ) {
			Try { # attempt to create and if fail - probably Horizon protected so INFO instead of FAIL
				# probably need to shut down VM before trying to add the setting
				New-AdvancedSetting -en $vm -name tools.guest.desktop.autolock -value 'FALSE' -Confirm:$false -ErrorAction 1 | Out-Null
				Write-Logs "FAIL" $vmName $autolockFunction "The tools.guest.desktop.autolock VM property is not set on $vmName Layer 2 VM. This can result in locked VMRC when VMRC is closed."
			} Catch {
				Write-Logs "INFO" $vmName $autolockFunction "Unable to create the tools.guest.desktop.autolock VM property on $vmName which is probably a solution-managed Layer 2 VM."
			}
			
		} Else {
		Write-Logs "INFO" $vmName $autolockFunction "The tools.guest.desktop.autolock VM property is set to $currentAutoLockValue on L2 $vmName."
		}
	}
} # End Check vVM Settings

##############################################################################
##### Check  Layer 2 VM Resource Settings
##############################################################################

# Report card #18 L2 VMs no CPU/Mem reservations or limits

If ( $vcPresent ) {
	Write-Output "Checking Layer 2 VM Resource Settings..." # check only no repair
}

$cpuFunction = "CPU reservation"
$memFunction = "Memory reservation"
$cpuSharesFunction = "CPU Shares"
$memSharesFunction = "Memory Shares"
Foreach ($vm in $allvms) {
	$vmName = $vm.Name
	If ( $vmName -Like "vCLS*" ) { Continue }
	If ( $vmName -Like "SupervisorControlPlaneVM*" ) { Continue }
	If ( $vm.VMResourceConfiguration.CpuReservationMhz ) { # attempt to change and if fail - probably NSX so INFO instead of FAIL
		$cpuRMHz = $vm.VMResourceConfiguration.CpuReservationMhz
		Try {
			$vm | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CPUReservationMhz 0 -ErrorAction 1
			Write-Logs "WARN" $vmName $cpuFunction "CPU reservation of $cpuRMHz MHz may prevent power on of $vmName in some clouds."	
		} Catch {
			Write-Logs "INFO" $vmName $cpuFunction "Cannot remove CPU reservation of $cpuRMHz MHz on solution-managed L2 $vmName which may prevent power on in some clouds."
		}
		Start-Sleep $sleepSeconds
	}
	If ( $vm.VMResourceConfiguration.MemReservationGB ) { # attempt to change and if fail - probably NSX so INFO instead of FAIL
		$memResGB = $vm.VMResourceConfiguration.MemReservationGB
		Try {
			$vm | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemReservationMB 0 -ErrorAction 1
			Write-Logs "WARN" $vmName $memFunction "Memory reservation of $memResGB cannot be guaranteed in L2 VMs. This may be problematic."
		} Catch {
			Write-Logs "INFO" $vmName $memFunction "Cannot remove memory reservation of $memResGB GB on solution-managed L2 $vmName which may be problematic some clouds."
		}
		Start-Sleep $sleepSeconds
	}
	If ( $vm.VMResourceConfiguration.CpuSharesLevel -ne "Normal" ) { # attempt to change and if fail - probably NSX so INFO instead of FAIL
		$cpuShares = $vm.VMResourceConfiguration.CpuSharesLevel
		Try {
			$vm | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CpuSharesLevel "normal" -ErrorAction 1
			Write-Logs "WARN" $vmName $cpuSharesFunction "$cpuShares CPU shares cannot be guaranteed on $vmName L2 VM. Please use normal shares."
		} Catch {
			Write-Logs "INFO" $vmName $cpuSharesFunction "$cpuShares CPU shares cannot be guaranteed on solution-managed $vmName L2 VM."
		}
		Start-Sleep $sleepSeconds
	}
	If ( $vm.VMResourceConfiguration.MemSharesLevel -ne "Normal" ) { # attempt to change and if fail - probably NSX so INFO instead of FAIL
		$memShares = $vm.VMResourceConfiguration.MemSharesLevel
		Try {
			$vm | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemSharesLevel "normal" -ErrorAction 1
			Write-Logs "WARN" $vmName $memSharesFunction "$memShares memory shares cannot be guaranteed on $vmName L2 VM. Please use normal shares."
		} Catch {
			Write-Logs "INFO" $vmName $memSharesFunction "$memShares memory shares cannot be guaranteed on solution-managed $vmName L2 VM."
		}
		Start-Sleep $sleepSeconds
	}
} # End Check vVM Resource Settings

##############################################################################
##### Check vSphere Licensing
##############################################################################

# Report card #13 vSphere license expiration (calculated based on vPod SKU lab year)
# Report card #14 No vCenter or vSphere Eval licenses

If ( $vcPresent ) {
	Write-Output "Checking vSphere Licensing..."
	Write-Output "vSphere license expiration date: $licenseExpireDate"

	#check for evaluation licenses in use
	$LM = Get-View LicenseManager -ErrorAction SilentlyContinue
	$LAM = Get-View $LM.LicenseAssignmentManager -ErrorAction SilentlyContinue
	$param = @($null)
	$assets = $LAM.QueryAssignedLicenses($param) # this works as of 12/12/2018
}

Foreach ($asset in $assets) {
	#Write-Host "asset: $asset"
	If ( $asset.AssignedLicense.LicenseKey -eq '00000-00000-00000-00000-00000' ) {
		# special case - make certain nothing is in evaluation mode
		$name = $asset | Select-Object -ExpandProperty EntityDisplayName
		Write-Logs "FAIL" $name $function "EVALUATION assignment"
	}
}
# query the license expiration for all installed licenses
Foreach( $license in ($LM | Select -ExpandProperty Licenses) ) {
	#Write-Host "license: $license"
	If ( !($license.LicenseKey -eq '00000-00000-00000-00000-00000') ) {
		$name = $License.Name
		$lKey = $License.LicenseKey
		$used = $License.Used
		$labels = $License.Labels | Select -ExpandProperty Value
		$expDate = $License.Properties | Where-Object {$_.Key -eq "expirationDate"} | Select-Object -ExpandProperty Value
		
		#Write-Output $name $lKey $used $labels $expDate

		If( -Not $expDate ) { $expDate = 'NEVER'}
		#Write-Output $expDate $chkDateMin $chkDateMax
	
		If( $expDate -And ( ( ($expDate -ge $chkDateMin) -Or ($expDate -ge $chkDateMin90) ) -And ($expDate -le $chkDateMax)) ) {
			$licenseStatus = "PASS"
			$output = "License $Name $lKey is good and expires $expDate"
			If( $used -eq 0 ) { # UNASSIGNED
				if( ($name -Like 'NSX *vSphere*Enterprise*') -Or ($name -Like 'NSX *vShield Endpoint*') ) {
					$licenseStatus = "INFO"
					$output = "Unassigned NSX licensing is expected."
				} Else {
					$licenseStatus = "FAIL"
					$output = "License $name is UNASSIGNED and should be removed."
				}
			}
		} Else {
			If( (! $expDate) -Or ( $expDate -eq "NEVER") ) {
				If( $Name -Like 'NSX *vShield Endpoint*' ) {
					$licenseStatus = "INFO"
					$output = "License $name $lKey NEVER expires but it usually does not."
				} ElseIf ($lKey -Like "*-XXXXX-*") {
					$licenseStatus = "INFO"
					$output = "Obfuscated license $name $lKey key NEVER expires but that is okay since it is hidden."
				} Else {
					$licenseStatus = "FAIL"
					$output = "License $name $lKey NEVER expires!!"
				}
			} Else {
				$licenseStatus = "FAIL"
				$output = "License $name $lKey is BAD. It expires $expDate"
			}
		}
		#If ( $licenseStatus -ne "PASS" ) { Write-Logs $licenseStatus $name $function $output }
		Write-Logs $licenseStatus $name "vSphere licensing" $output
	}
} # End Check vSphere Licensing

# End legacy vPodChecker code

##############################################################################
##### Begin vSphere configuration checks
##############################################################################

#35 Storage policy not impacting I/O (flag for manual review)

If ( $vcPresent ) {
	Write-Output "Checking vSphere Storage Policies..."

	# added more storage policies with vSphere 7 4/8/2020
	# set the base version number for each storage policy
	$defaultStoragePolicyNames = @{ 
"Host-local PMem Default Storage Policy" = "0"
"Management Storage policy - Encryption" = "0"
"Management Storage policy - Large" = "1"
"Management Storage policy - Regular" = "1"
"Management Storage policy - Single Node" = "0"
"Management Storage policy - Stretched" = "0"
"Management Storage policy - Stretched Lite" = "0"
"Management Storage Policy - Stretched ESA" = "0"
"Management Storage policy - Thin" = "0"
"VM Encryption Policy" = "0"
"vSAN Default Storage Policy" = "2"
"vSAN ESA Default Policy - RAID5"  = "0"
"vSAN ESA Default Policy - RAID6"  = "0"
"vSAN Stretched ESA Default Policy - RAID5" = "0"
"vSAN Stretched ESA Default Policy - RAID6" = "0"
"vSAN Stretched ESA Default Policy" = "0"
"cluster-mgmt-01a vSAN Storage Policy" = "0"
"cluster-wld01-01a vSAN Storage Policy" = "0"
"VVol No Requirements Policy" = "0"
}

	$sPolicyCheck = "PASS"
	Try {
		$sPolicies = Get-SpbmStoragePolicy -ErrorAction SilentlyContinue -ErrorVar errorVar
		Foreach ($sPolicy in $sPolicies) {
			$sName = $sPolicy.Name
			$sVersion = $sPolicy.Version
			If ( ($defaultStoragePolicyNames[$sName] ) -And ($sPolicy.Version -ne [int]$defaultStoragePolicyNames[$sName]) ) {
				# this sPolicy has been changed, it needs to be reviewed
				$sPolicyCheck = "WARN"
				Write-Logs "INFO" $sName "Storage Policies" "$sName version $sVersion has been changed from the default. Requires manual review."
			}
			If ( -Not $defaultStoragePolicyNames[$sName] ) {
				$sPolicyCheck = "FAIL"
				Write-Logs "INFO" $sName "Storage Policies" "$sName is not a default Storage Polcy. Requires manual review."
			}
		}
	} Catch {
		Write-Output "Catch: $errorVar"
	}
	If ($sPolicyCheck -eq "PASS" ) {
		Write-Logs "PASS" "vSphere" "Storage Policies" "No changes in Storage Policies from defaults."
	}
}

#37 DRS set to Partial or Off - not Full or Manual
#38 vSphere HA Disabled (unless required for demo) - updated standard 12-May 2025 HA enabled
If ( $vcPresent ) { 
	Write-Output "Checking vSphere cluster DRS and HA configurations..."
	$allClusters = Get-Cluster -ErrorAction SilentlyContinue
}
Foreach ($cluster in $allClusters) {
	#Write-Output $cluster.Name "HA: " $cluster.HAEnabled " DRS: " $cluster.DrsEnabled " DRS Automation Level: " $cluster.DrsAutomationLevel
	If ( $cluster.HAEnabled ) {
		Write-Logs "INFO" $cluster.Name "HA Status" "HA is enabled on $cluster."
	} Else {
		Write-Logs "PASS" $cluster.Name "HA Status" "HA is not enabled on $cluster."
	}
	If ( $cluster.DrsEnabled -and ($cluster.DrsAutomationLevel -eq "FullyAutomated") ) {
		Write-Logs "WARN" $cluster.Name "DRS Configuration" "DRS is fully automated on $cluster. Please use partial or off."
	} Else {
		Write-Logs "PASS" $cluster.Name "DRS Configuration" "DRS is configured correctly on $cluster."
	}
}

##############################################################################
##### Check ESXi Claim Rules
##############################################################################
#39 If using VSAN, Explicit HDD and SSD flags configured

If ( $vcPresent ) { 
	[Console]::Write("Collecting vESXi Claim Rules...") # show progress with dots ..."
	$VMHosts = Get-VMHost -ErrorAction SilentlyContinue
}
Foreach ( $VMHost in $VMHosts ) {
	If ( $VMHost.model -eq "VMware Mobility Platform" ) { Continue } # skipping the "ghost" ESXi hosts that HCX uses
	[Console]::Write(".")
	$report = @()
	$hostName = $VMHost.Name
	$scsiLuns = Get-ScsiLun -VMHost $VMHost -LunType "disk"
	ForEach ( $scsiLun in $scsiLuns ) {
		$LUN_CName = $scsiLun.CanonicalName
		$EsxCli = $VMHost | Get-EsxCli -V2
		Try {
			$claimRules = $EsxCli.storage.nmp.satp.rule.list.Invoke()
			Foreach ( $rule in $claimRules ) {
				if ( $rule.Device -eq $LUN_CName ) {
					#$line = ""| select Hostname, Device, Options, IsSSD
					$device = $rule.Device
					$options = $rule.Options
					$isSSD = (Get-ScsiLUN -CanonicalName $LUN_CName -VMhost $VMHost).ExtensionData.Ssd 
					$report += "Host: $hostName Devicd: $device Options: $options SSD: $isSSD`n"
					#Write-Output "host: $hostName device: $device options: $options SSD: $isSSD"
				}
			}
		} Catch {
			Write-Logs "INFO" $target "ESXi Claim Rules" "Unable to retrieve claim rules on $target"
		}
	}
	If ( $report ) {
		Write-Logs "INFO" $VMHost.Name "ESXi Claim Rules" $report
	} Else {
		$target = $VMHost.Name
		Write-Logs "INFO" $target "ESXi Claim Rules" "No claim rules found on $target"
	}
}
Write-Output ""