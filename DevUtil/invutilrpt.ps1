
$autocheckModulePath = "$PSSCriptRoot/autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

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

# just change the CSV to use - keep the object name consistent
$content = Get-Content -Path ".\layer1linux-sav.csv"

$Layer1Linux = @{}

$ctr = 1
ForEach ( $line in $content ) { 
	$line = $line.Replace('"', '')
	#"Name","OS","dnsName","ipAddress","dnsIP","Layer","ssh","account","PuTTY","uname","sshAuth"
	($Name,$OS,$dnsName,$ipAddress,$dnsIP,$Layer,$ssh,$account,$PuTTY,$uname,$sshAuth) = $line.Split(',')
	If ( $ipAddress -eq "ipAddress" ) { Continue }
	If ( $ipAddress -eq $null ) { Continue }
	
	$lm = New-Object -TypeName psobject
	$lm | Add-Member -MemberType NoteProperty -Name Name -Value $Name
	$lm | Add-Member -MemberType NoteProperty -Name OS -Value $OS
	$lm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$lm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $ipAddress
	$lm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$lm | Add-Member -MemberType NoteProperty -Name Layer -Value $Layer
	$lm | Add-Member -MemberType NoteProperty -Name ssh -Value $ssh
	$lm | Add-Member -MemberType NoteProperty -Name account -Value $account
	$lm | Add-Member -MemberType NoteProperty -Name PuTTY -Value $PuTTY
	$lm | Add-Member -MemberType NoteProperty -Name uname -Value $uname
	$lm | Add-Member -MemberType NoteProperty -Name sshAuth -Value $sshAuth
	#Write-Host "name: $name ipAddress: $ipAddress"
	$Layer1Linux[$ipAddress] = $lm	
	$ctr++
}

<#
Foreach ( $ipTarget in $Layer1Linux.keys ) {
		$Layer1Linux[$ipTarget]
}
Exit 0
#>

# just change the CSV to use - keep the object name consistent
$content = Get-Content -Path ".\layer1windows.csv"

$Layer1Windows = @{}

$ctr = 1
ForEach ( $line in $content ) { 
	$line = $line.Replace('"', '')
	#"Name","OS","dnsName","ipAddress","dnsIP","Layer","ssh","account","PuTTY","uname","sshAuth"
	($Name,$OS,$dnsName,$ipAddress,$dnsIP,$Layer) = $line.Split(',')
	If ( $ipAddress -eq "ipAddress" ) { Continue }
	If ( $ipAddress -eq $null ) { Continue }
	
	$wm = New-Object -TypeName psobject
	$wm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$wm | Add-Member -MemberType NoteProperty -Name OS -Value ($os.Trim())
	$wm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$wm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$wm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$wm | Add-Member -MemberType NoteProperty -Name Layer -Value "1"
	
	$Layer1Windows[$IPAddress] = $wm
	#Write-Host "name: $name ipAddress: $ipAddress"
	$ctr++
}

<#
Foreach ( $ipTarget in $Layer1Windows.keys ) {
		$Layer1Windows[$ipTarget]
}
Exit 0
#>

# layer 1 storage utilization to avoid shadow exports
$storagethreshold = 50

#### Inventory Report ####

Write-Output "Generating inventory utilization report..."
$invUtilReport = Join-Path -Path $logDir -ChildPath "$vPodName-invutilrpt.txt"
Set-Content -Path "$invUtilReport" -Value "" -NoNewline # overwrite existing log file


# Layer 1 report on CPU utilization, memory utilization and storage utilization
Write-Output "Working on Layer 1 Linux Utilization..."
Write-Output "############ Layer 1 Linux Utilization ############" | Add-Content $invUtilReport
$topCmd = "top -bn1"
$storageCmd = "df -h"
$report = @()
Foreach ($ipTarget in $Layer1Linux.keys) {
	$item = "" | Select Name, CPU, Memory, Storage
	If ( $Layer1Linux[$ipTarget].Name -Like "*esx-*" ) { Continue } # will get vESXi utilization from vCenter (no top)
	If ( $ipTarget -eq $stgIP ) { Continue } # FreeNAS BSD top is different
	If ( $ipTarget -eq $rtrIP ) { Continue } # vpodrouterHOL is most likely not an issue can investigate later
	If ( $ipTarget -eq "192.168.0.2" ) { Continue } # other vpodrouterHOL IP
	If ( $ipTarget -eq $mgrIP) { Continue } # Manager VM skip
	$item.Name = $Layer1Linux[$ipTarget].Name
	$hostName = $item.Name
	$target = $hostname + "(" + $ipTarget + ")"
	#Write-Output "L1 Linux utilization for $hostName"
	Try {
		$output1 = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $topCmd
		# kind of crazy that I have to round trip to a file to not get one long line
		$output1 | Set-Content "/tmp/top.txt"
		$output = Get-Content "/tmp/top.txt"
		If ( $Layer1Linux[$ipTarget].uname -Like "*photon*" ) {
			ForEach ( $line in $output ) {
				$line = $line -Replace '\s+', ' '
				If ( $line -Like "*Cpu*" ) {
					$fields = $line.Split()
					($c, $junk) = $fields[3].Split('[')
					$cpuTotal += [float]$c
				}
				If ( $line -Like "*Mem*" ) {
					$fields = $line.Split()
					($memPercent,$junk) = $fields[3].Split('/')
					Break 
				}
			}
			$item.CPU =  "{0:N2}%" -f ([float]$cpuTotal)
			$item.Memory = "{0:N2}%" -f ([float]$memPercent)
		} Else {
			ForEach ( $line in $output ) {
				If ( $line -Like "*Cpu*" ) { 
					$cpuLine = $line
					Break			
				}
			}
			$cpuLine = $cpuLine -Replace '%', ' '
			$cpuLine = $cpuLine -Replace '\s+', ' '
			$cpuFields = $cpuLine.Split(',')
			Foreach ( $f in $cpuFields ) { # need to account for some variability in top output
				If ( $f -Like "*id*" ) {
					$f = $f.Trim()
						($idle, $junk) = $f.Split()
				Break
				}
			}
			$item.CPU =  "{0:N2}%" -f (100-[float]$idle)
	
			ForEach ( $line in $output ) {
				If ( $line -Like "*Mem*" ) { 
					$memLine = $line
					Break
				}				
			}
			$memLine = $memLine -Replace 'k', ' '
			$memLine = $memLine -Replace '\s+', ' '
			$memFields = $memLine.Split(',')
			Foreach ( $f in $memFields ) { # need to account for some variability in top output
				If ( $f -Like "*total*") {
					($junk, $t) = $f.Split(':')
					$t = $t.Trim()
					($totalMem, $junk) = $t.Split()
					If ( $totalMem -Like "*M" ) { $totalMem = $totalMem -Replace 'M', '' } # SUSE
					$totalGB = $totalMem /1024 /1024
				}
				If ( $f -Like "*used*") {
					$f = $f.Trim()
					($usedMem, $junk) = $f.Split()
					If ( $usedMem -Like "*M" ) { $usedMem = $usedMem -Replace 'M', '' } # SUSE
					$usedGB = $usedMem /1024 /1024
					Break
				}
			}
			$item.Memory = "{0:N2}%" -f (($usedGB / $totalGB) *100)
		}
	
		$topUsePercent = 0
		$output1 = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $storageCmd
		$output1 | Set-Content "/tmp/stg.txt"
		$output = Get-Content "/tmp/stg.txt"
		Remove-Item "stg.txt"
		Foreach ( $line in $output ) {
			If ( (-Not ($line -Like '*%*')) -Or ($line -Like '*Use%*') ) { Continue }
			If ( $line -Like "/dev/loop*" ) { Continue }
			$f = ($line -Replace '\s+', ' ').Split()
			$usePercent = $f[4].Trim("%")
			If ( [int]$usePercent -gt [int]$topUsePercent ) { $topUsePercent = $usePercent }
		}
		$item.Storage = "{0:N2}%" -f $topUsePercent
		if ( $topUsePercent  -gt $storagethreshold ) {
			Write-Logs "FAIL" $hostName "Storage Use" "Layer 1 VM $hostName is using more than ${storagethreshold}% which causes shadows to FAIL"
		}
	
		$report += $item
	} Catch {
		[String]$err = $errorVar
		$err = $err.Trim() # remove the newline
		Write-Output "Catch errorVar: $err"
		Write-Output "Catch wcmd: $wcmd Layer 1 Linux: " $item.Name
	}
}

$output = $report | Sort-Object -Descending -Property Memory | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

Write-Output "Working on Layer 1 Windows Utilization..."
Write-Output "############ Layer 1 Windows Utilization ############" | Add-Content $invUtilReport
$report = @()
Foreach ($ipTarget in $Layer1Windows.keys) {
	
	$item = "" | Select Name, CPU, Memory, Storage
	$item.Name = $Layer1Windows[$ipTarget].Name	
	$hostName = $item.Name
	#Write-Output "L1 Windows utilization for $hostName"
	
	# CPU use average percentage
	$cpuAvgScript = '"Powershell.exe -Command \"Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average\""'
	"/usr/bin/python3 runwincmd.py $ipTarget Administrator $password $cpuAvgScript" | Set-Content "/tmp/cpuavg.sh"
	$output1 = Invoke-Expression -Command "/bin/sh /tmp/cpuavg.sh" -ErrorVariable errorVar
	$output1 | Set-Content "/tmp/output.txt"
	$output = Get-Content "/tmp/output.txt"
	$fields = $output.Split('\r')
	$cpu = $fields[3].Replace("'", "" )
	$cpu = $cpu.Replace(",", "" )
	$item.CPU = $cpu.Trim() + "%"
	#Write-Host "item.CPU: $item.CPU"
	
	# memory use percentage
	$memCmd = "systeminfo"
	"/usr/bin/python3 runwincmd.py $ipTarget Administrator $password $memCmd" | Set-Content "/tmp/mem.sh"
	$output1 = Invoke-Expression -Command "/bin/sh /tmp/mem.sh" -ErrorVariable errorVar
	$output1 | Set-Content "/tmp/output.txt"
	$output = Get-Content "/tmp/output.txt"
	$output = $output1.Split("\r")
	Foreach ( $line in $output ) {
		If ( $line -Like "*Total Physical Memory*" ) {
			($junk, $keep) = $line.Split(":")
			($totalMemMB, $junk) = ($keep.Trim()).Split()
			$totalMemMB = $totalMemMB.Replace(',','')		
		}
		If ( $line -Like "*Available Physical Memory*" ) {
			($junk, $keep) = $line.Split(":")
			($availMemMB, $junk) = ($keep.Trim()).Split()
			$availMemMB = $availMemMB -Replace ',', ''			
			Break
		}
	}
	$item.Memory = "{0:N2}%" -f ((($totalMemMB - $availMemMB) / $totalMemMB) * 100)

	$topUsePercent = 0
	$storageCmd = '"wmic logicaldisk get caption,drivetype,freespace,size"'
	"/usr/bin/python3 runwincmd.py $ipTarget Administrator $password $storageCmd" | Set-Content "/tmp/storage.sh"
	$output1 = Invoke-Expression -Command "/bin/sh /tmp/storage.sh" -ErrorVariable errorVar
	$output1 | Set-Content "/tmp/output.txt"
	$output = Get-Content "/tmp/output.txt"
	$output = $output1.Split("\r")
	Foreach ( $line in $output) {
		If ( $line -Like "*Caption*DriveType*FreeSpace*Size*" ) { Continue }
		If ( $line -eq "" ) { Continue }
		$line = $line.Replace("'",'')
		$line = $line.Replace(",",'')
		$line = $line.Replace(",",'')
		$line = $line.Replace("]",'')
		$line = $line -Replace("\s+", "~")
		If ( $line -NotLike "*~3~*" ) { Continue }  # only local disks
		$fields = $line.Split("~")
		$dCaption = $fields[1]
		$dType = $fields[2]
		$freeTmp = $fields[3]
		$sizeStr = $fields[4]	
		#Write-Output "dCaption: $dCaption dType: $dType freeTmp: $freeTmp sizeTmp: $sizeTmp
		$free = $freeTmp / 1GB
		$size = $sizeStr / 1GB
		$usePercent = (($size - $free) / $size) * 100
		If ( [int]$usePercent -gt [int]$topUsePercent ) { $topUsePercent = $usePercent }
		#Write-Output "free: $free size: $size usePercent: $usePercent topUsePercent: $topUsePercent"
		Break
	}
	$item.Storage = "{0:N2}%" -f $topUsePercent
	if ( $topUsePercent  -gt $storagethreshold ) {
		Write-Logs "FAIL" $hostName "Storage Use" "Layer 1 VM $hostName is using more than ${storagethreshold}% which causes shadows to FAIL"
	}
	$report += $item
}

$output = $report | Sort-Object -Descending -Property Memory | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

#>

# report on vESXi CPU utilization, Memory Utilization
$report = @()
If ( $vcPresent ) {
	Write-Output "Working on vESXi Utilization..."
	Write-Output "############ vESXi Utilization ############" | Add-Content $invUtilReport
	$esxHosts = Get-VMHost
}
Foreach ( $esxHost in $esxHosts ) {
	$item = "" | Select Name, CPU, Memory
	$item.Name = $esxHost.Name
	$item.CPU = "{0:N2}%" -f (($esxHost.CpuUsageMhz / $esxHost.CpuTotalMhz)*100)
	$item.Memory = "{0:N2}%" -f (($esxHost.MemoryUsageMB / $esxHost.MemoryTotalMB)*100)
	#Write-Output $esxHost.Name " CPU: $cpuPercentUtil Memory: $memPercentUtil`n" | Add-Content $invUtilReport -NoNewLine
	$report += $item
}

$output = $report | Sort-Object -Descending -Property Memory | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

#report on datastore usage
$report = @()
If ( $vcPresent ) {
	Write-Output "Working on Datastore Usage..."
	Write-Output "############ Datastore Usage ####################" | Add-Content $invUtilReport
	$datastores = Get-Datastore
}
Foreach ($datastore in $datastores) {
	$item = "" | Select Name, CapacityGB, FreeSpaceGB, UsedGB, PercentUsed
	$item.Name = $datastore.Name
	$item.CapacityGB = "{0:N2}" -f ($datastore.CapacityMB / 1024)
	$item.FreeSpaceGB = "{0:N2}" -f ($datastore.FreeSpaceMB / 1024)
	$usedGB = "{0:N2}" -f ($item.CapacityGB - $item.FreeSpaceGB)
	$item.UsedGB = $usedGB
	[float]$totalUsedGB += [float]$usedGB
	$item.PercentUsed = "{0:N2}%" -f (($usedGB / $item.CapacityGB)*100)
	#Write-Output $datastore.Name "Capacity " $capacityGB "GB Free: " $freeSpaceGB "GB Percent Used: " $percentUsed "`n" 
	$report += $item
}
$output = $report | Sort-Object -Descending -Property PercentUsed | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII
$output = "Total Used GB: {0:N2}`n" -f [float]$totalUsedGB
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

#get L2 inventory
$report = @()
If ( $vcPresent ) {
	Write-Output "Working on Layer 2 VMs..."
	Write-Output "################## Layer 2 VMs Inventory ######################" | Add-Content $invUtilReport
	$VMs = Get-VM
}

Foreach ($vm in $VMs) {
	$item = "" | Select Name, NumCPU, MemoryGB, StorageGB, Power, ESXHost
	If ( $vm.Name -Like "*vCLS*" ) { $item.Name = $vm.Name.SubString(0,13)
	} Else { $item.Name = $vm.Name } 
	$item.NumCPU = $vm.NumCpu
	$item.MemoryGB = "{0:N2}" -f ($vm.memoryGB)
	$item.StorageGB = "{0:N2}" -f ($vm.ProvisionedSpaceGB)
	$sumUsedGB += $vm.UsedSpaceGB
	If ( $vm.PowerState -eq "PoweredOff" ) {
		$item.Power = "Off"
	} Else {
		$item.Power = "On"
	}
	$vmHost =  $vm.VMHost.Name
	$parts = $vmHost.Split(".")
	$item.ESXhost = $parts[0]
	$report += $item
}
$output = $report | Sort-Object -Property ESXhost | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII
Write-Output "-----------" | Add-Content $invUtilReport
$sum = "{0:N2}" -f ($sumUsedGB)
Write-Output "Total Layer 2 storage used: ${sum}`n"  | Add-Content $invUtilReport

#get L2 performance data from vCenter similar to L1 show percent CPU, mem and storage
$report = @()
If ( $vcPresent ) { 
	Write-Output "################## Layer 2 VMs Utilization ######################" | Add-Content $invUtilReport
}

Foreach ($vm in $VMs) {
	$item = "" | Select Name, CPU, Memory, Storage
	If ( $vm.Name -Like "*vCLS*" ) { $item.Name = $vm.Name.SubString(0,13)
	} Else { $item.Name = $vm.Name } 
	If ( $vm.PowerState -eq "PoweredOff" ) {
		$item.CPU = 0
		$item.Memory = 0
	} Else {
		$cpuStat = Get-Stat -Stat "cpu.usage.average" -MaxSamples 1  -Entity $vm -Realtime
		$item.CPU = "{0:N2}%" -f ($cpuStat.Value)
		$memStat = Get-Stat -Stat "mem.usage.average" -MaxSamples 1  -Entity $vm -Realtime
		$item.Memory = "{0:N2}%" -f ($memStat.Value)
	}
	$item.Storage = "{0:N2}%" -f ( ($vm.UsedSpaceGB / $vm.ProvisionedSpaceGB) * 100)
	$report += $item
}
$output = $report | Sort-Object -Property Name | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII
Write-Output "-----------" | Add-Content $invUtilReport
# copy to simple name for AutoCheck HTML report
Copy-Item $invUtilReport "$logDir/HTML/invutilrpt.tx"
