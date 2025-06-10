$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''
 
##############################################################################
##### BEGIN HERE
##############################################################################

# TESTING one L1 VM from the command line

$linux = $true
$windows = $false
$hostName = "router"
$ipTarget = "192.168.100.1"
#$target = $hostname + "(" + $ipTarget + ")"

$invUtilReport = $logDir + "\$vPodName-invutilrpt.txt"
Set-Content -Path "$invUtilReport" -Value "" -NoNewline # overwrite existing log file

# Layer 1 report on CPU utilization, memory utilization and storage utilization

$report = @()

$item = "" | Select Name, CPU, Memory, Storage
$item.Name = $hostName
If ( $linux ) {
	Write-Output "############ Layer 1 Linux Utilization ############" | Add-Content $invUtilReport
	$topCmd = "top -bn1"
	$wcmd = "Echo Y | $plinkPath -ssh $ipTarget -l root -pw VMware1! $topCmd  2>&1"
	$output1 = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$output = $output1.Split("`r`n")
	$cpuLine = $output[2]
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
	
	$memLine = $output[3]
	$memLine = $memLine -Replace 'k', ' '
	$memLine = $memLine -Replace '\s+', ' '
	$memFields = $memLine.Split(',')
	Foreach ( $f in $memFields ) { # need to account for some variability in top output
		If ( $f -Like "*total*") {
			($junk, $t) = $f.Split(':')
			$t = $t.Trim()
			($totalMem, $junk) = $t.Split()
			$totalGB = $totalMem /1024 /1024
		}
		If ( $f -Like "*used*") {
			$f = $f.Trim()
			($usedMem, $junk) = $f.Split()
			$usedGB = $usedMem /1024 /1024
			Break
		}
	}
	$item.Memory = "{0:N2}%" -f (($usedGB / $totalGB) *100)
	
	$storageCmd = "df -h"
	$topUsePercent = 0
	$wcmd = "Echo Y | $plinkPath -ssh $ipTarget -l root -pw VMware1! $storageCmd  2>&1"
	$output1 = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$output = $output1.Split("`r`n")
	Foreach ( $line in $output ) {
		If ( (-Not ($line -Like '*%*')) -Or ($line -Like '*Use%*') ) { Continue }
		$f = ($line -Replace '\s+', ' ').Split()
		$usePercent = $f[4].Trim("%")
		If ( [int]$usePercent -gt [int]$topUsePercent ) { $topUsePercent = $usePercent }
	}
	$item.Storage = "{0:N2}%" -f $topUsePercent
	
	$report += $item
}

If ( $windows)  {
	Write-Output "############ Layer 1 Windows Utilization ############" | Add-Content $invUtilReport
	$cpuAvgScript = 'Powershell.exe -Command `"Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average`"'
	$wcmd = "$psexecPath \\$ipTarget -nobanner cmd /c `"$cpuAvgScript`" > $TMPlogDir\output.txt 2>&1" # this is done to keep it quiet
	$output1 = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$output1 = Get-Content -Path $TMPlogDir\output.txt
	$output = $output1.Split("`r`n")
	$item.CPU = $output[3].Trim() + "%"
	
	$memCmd = "systeminfo"
	$wcmd = "$psexecPath \\$ipTarget -nobanner cmd /c `"$memCmd`" > $TMPlogDir\output.txt 2>&1" # this is done to keep it quiet
	$output1 = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$output1 = Get-Content -Path $TMPlogDir\output.txt
	$output = $output1.Split("`r`n")
	Foreach ( $line in $output ) {
		If ( $line -Like "*Total Physical Memory*" ) {
			($junk, $keep) = $line.Split(":")
			($totalMemMB, $junk) = ($keep.Trim()).Split()
			$totalMemMB = $totalMemMB -Replace ',', ''
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
	$storageCMD = "wmic logicaldisk get size,freespace,caption"
	$wcmd = "$psexecPath \\$ipTarget -nobanner cmd /c `"$storageCmd`" > $TMPlogDir\output.txt 2>&1" # this is done to keep it quiet
	$output1 = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	$tmp
	$output1 = Get-Content -Path $TMPlogDir\output.txt
	$output = $output1.Split("`r`n")
	#$output
	Foreach ( $line in $output) {
		If ( $line -Like "*Caption*FreeSpace*Size*" ) { Continue }
		If ( $line -Like "*Connecting to*" ) { Break }
		($junk, $freeTmp, $sizeTmp) = ($line -Replace '\s+', '~').Split("~")
		If ( -Not $sizeTmp ) { Continue }
		$sizeStr = [string]$sizeTmp # yeah - weird
		$free = $freeTmp / 1GB
		$size = $sizeStr / 1GB
		$usePercent = (($size - $free) / $size) * 100
		If ( [int]$usePercent -gt [int]$topUsePercent ) { $topUsePercent = $usePercent }
	}
	$item.Storage = "{0:N2}%" -f $topUsePercent
	$report += $item
}

$output = $report | Sort-Object -Descending -Property Memory | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

Exit

Set-Variable -Name "VCENTERS" -Value $(Read-FileIntoArray "VCENTERS")
$vcsToTest = @()
Foreach ($entry in $vCenters) {
	($vc,$type) = $entry.Split(":")
	 $vcsToTest += $vc 
}

Write-Output "Checking vCenter connections..."
Foreach ($vcserver in $vcsToTest) { 
	$errorVar = Connect-VC $vcserver $vcuser $password ([REF]$result)
	If ( $result -eq "success" ) {
		Write-Logs "PASS" $vcserver "vCenter connection" "$vcserver connection successful" 
	} Else {
		Write-Logs "FAIL" $vcserver "vCenter connection" "Failed to connect to server $vcserver $errorVar"
	}
}


# report on vESXi CPU utilization, Memory Utilization
Write-Output "############ vESXi Utilization ############" | Add-Content $invUtilReport
$report = @()
$esxHosts = Get-VMHost
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
Write-Output "############ Datastore Usage ####################" | Add-Content $invUtilReport
$report = @()
$datastores = Get-Datastore
Foreach ($datastore in $datastores) {
	$item = "" | Select Name, CapacityGB, FreeSpaceGB, PercentUsed
	$item.Name = $datastore.Name
	$item.CapacityGB = "{0:N2}" -f ($datastore.CapacityMB / 1024)
	$item.FreeSpaceGB = "{0:N2}" -f ($datastore.FreeSpaceMB / 1024)
	$usedGB = "{0:N2}" -f ($item.CapacityGB - $item.FreeSpaceGB)
	$item.PercentUsed = "{0:N2}%" -f (($usedGB / $item.CapacityGB)*100)
	#Write-Output $datastore.Name "Capacity " $capacityGB "GB Free: " $freeSpaceGB "GB Percent Used: " $percentUsed "`n" 
	$report += $item
}
$output = $report | Sort-Object -Descending -Property PercentUsed | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII

#TODO: Need to get storage free for L1

#get L2 inventory
Write-Output "################## Layer 2 VMs ######################" | Add-Content $invUtilReport
$report = @()
$VMs = Get-VM
Foreach ($vm in $VMs) {
	$item = "" | Select Name, NumCPU, MemoryGB, DiskZeroGB, TotalUsedGB, ESXhost
	$item.Name = $vm.Name
	$item.NumCPU = $vm.NumCpu
	$item.MemoryGB = "{0:N2}" -f ($vm.memoryGB)
	$item.DiskZeroGB = "{0:N2}" -f (($vm|Get-HardDisk)[0].CapacityGB)
	$item.TotalUsedGB = "{0:N2}" -f ($vm.UsedSpaceGB)
	$sumUsedGB += [float]$item.TotalUsedGB
	$item.ESXhost = $vm.VMHOST
	$report += $item
	#$output += "$name $memGB $diskZeroCapacityGB $diskZeroUsedGB $vmhost`n"
}
$output = $report | Sort-Object -Property ESXhost | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII
Write-Output "-----------" | Add-Content $invUtilReport
$sum = "{0:N2}" -f ($sumUsedGB)
Write-Output "Total Layer 2 storage used: $sum"  | Add-Content $invUtilReport

# final cleanup

Foreach( $vcserver in $vcsToTest ) {
	#Write-Output "$(Get-Date) disconnecting from $vcserver ..."
	Disconnect-VIServer -Server $vcserver -Confirm:$false
}
