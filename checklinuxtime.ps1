# checklinuxtime.ps1 25-April 2025
# updated 7/15/2020 Re-implemented time sync checking to handle all the known Linux and VMware appliance mechanisms
# updated 7/23/2020 added ntpStatus NOSYNC to deal with Photon configuration correct but not NTP syncing
# updated 1/24/2021 refined CentOS chronyc detection (2173 saltstack.$dom)
# updated 1/24/2021 refined Photon OS time sync using systemctl status systemd-timesyncd (2173 dev-tools)
# updated 4/30/2021 first pass implementing for use by LMC - further testing probably needed.
# updated 7/24/2021 updated LMC plink still need more testing.
# updated 6/3/2023 Photon appears to be using /etc/ntp.conf now and chronyc also works
# updated 6/3/2023 On LMC catch remoteLinuxCmdLMC error and use last element only.

$autocheckModulePath = Join-Path $PSSCriptRoot -ChildPath "autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Host "Abort."
	Exit
}

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

# need arguments
$hostName = $args[0]
$ipTarget = $args[1]
$uname = $args[2]
$account = $args[3]

$target = $hostName + "(" + $ipTarget + ")"

#Write-Host $hostNAme $ipTarget $uname $account
# define a flag to indicate ntp status since there are multiple ways to check ntp
$ntpStatus = 'FAIL' # start with FAIL as default

# define a flag to note a vCenter that does not have the shell enabled
$vCenterNoShell = $false

# Photon systemctl /etc/systemd/timesyncd.conf
$photonConfCmd  = @"
"grep ^NTP /etc/systemd/timesyncd.conf"
"@

# traditional method
$ntpConfCmd = @"
"grep ^server /etc/ntp.conf"
"@

$ntpqCmd  = @"
"ntpq -p  | grep \*"
"@

# 7/5/2020 CentOS now uses "chronyc sources" by default instead of NTP
$ntpChronycCmd = @"
"chronyc sources | grep ^\^"
"@

# 6/15/2020 newer versions of Photon do not use /etc/ntp.conf or ntpq but not all versions support show-timesync
$ntpCmd3 = @"
"timedatectl show-timesync | grep ServerAddress | cut -f2 -d'='"
"@

$ntpCmd3a = @"
"timedatectl | grep ^NTP | cut -f2 -d':'"
"@

# later version of Photon (2173 dev-tools)
# https://kb.vmware.com/s/article/76088
$ntpCmd3b = @"
"systemctl status systemd-timesyncd | grep Status | cut -f2 -d":""
"@

# 7/5/2020 Horizon Identity Manager used Tools timesync
$ntpCmd4 = "/usr/bin/vmware-toolbox-cmd timesync status"

# 6/15/2020 vRA checks NTP this way
$ntpCmd5 = "vracli ntp show-config"

# 7/30/2020
$dateCmd = 'date -u +%a,%d,%b,%Y,%H:%M:%S'

# Define the tolerance for time delta between local and remote machines
$timeDiffTolerance = 30
$timeTolerance = New-Timespan -Second $timeDiffTolerance
$tolSec = $timeTolerance.Seconds

# tinycore is an exception - no NTP
If ( $uname -Like "*tinycore*" ) {
	$ntpConf = "notfound"
	$ntpStatus = "PASS"
	$logMessage = "tinycore does not have NTP installed."
} ElseIf ( $uname -Like "*centos*" ) {
	$centos = $True
}

# start with Photon OS time sync "grep ^NTP /etc/systemd/timesyncd.conf"
If ( $uname -Like "*photon*" -And $ntpStatus -eq "FAIL" ) {
	Try {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $photonConfCmd
		#Write-Host "photonConfCmd output: $output"
		If ( $output -Like "*Unknown command:*" ) {
			#Write-Host "vCenter $hostName is running appliance shell."
			$vCenterNoShell = $true
			$output1 = remoteLinuxCmdLMC $ipTarget $account $linuxpassword "com.vmware.appliance.ntp.get"
			# need to get the output into an array
			$output1 | Set-Content "/tmp/output.txt"
			$output = Get-Content "/tmp/output.txt"
			#Write-Host "vCenter appliance output: $output"			
		}		 
		$ntpConf = Choose-TimeSource $output
		#Write-Host "ntpConf: $ntpConf"
		If ( $ntpConf -eq "invalid" ) { $logMessage = "NTP configuration etc/systemd/timesyncd.conf is using an invalid time server: $output" }
		If ( $ntpConf -eq "notfound" ) { $logMessage = "NTP configuration etc/systemd/timesyncd.conf is not found." }
	} Catch {
		#Write-Host "Catch photonConfCmd output: $photonConfCmd $output"
		$logMessage = "NTP configuration etc/systemd/timesyncd.conf is not found."
		$ntpConf = 'notfound'
	}
	If ( ( $ntpConf -Like "*ntp*" ) -Or ( $ntpConf -Like "*Servers:*" ) -Or $ntpConf -eq 'notfound' ) {
		Try {
			If ( $vCenterNoShell -And ( $ntpConf -ne 'notfound' ) ) {
				($junk, $server) = $ntpConf.Split(":")
				#Write-Host "remoteLinuxCmdLMC $ipTarget $account $linuxpassword com.vmware.appliance.ntp.test --servers $server"
				$output1 = remoteLinuxCmdLMC $ipTarget $account $linuxpassword "com.vmware.appliance.ntp.test --servers $server"
				# need to get the output into an array
				$output1 | Set-Content "/tmp/output.txt"
				$output = Get-Content "/tmp/output.txt"
				#Write-Host "vCenter appliance output: $output"
			} Else {
				$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpCmd3a # timedatectl | grep ^NTP
				#Write-Host "ntpCmd3a output: $ntpCmd3a $output"
				$ntpConf = Choose-TimeSource $output
				#Write-Host "ntpConf: $ntpConf"
			}
			If  ( $output -Like "*yes*" ) {
				$ntpStatus = "PASS"
				$logMessage = "Photon OS NTP configuration is good: $ntpConf and NTP syncronization is enabled."
			} ElseIf ( !$output ) { # newer version of Photon, try ntpCmd3b
				$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpCmd3b
				If ( $output -Like "*Synchronized*" ) {
					$ntpStatus = "PASS"
					$output = $output.Substring(2) # get rid of the leading space and double quote
					$logMessage = "Photon OS NTP configuration is good: $output"
				}
			} ElseIf ( $output -Like "*Status: SERVER_REACHABLE*" ) {				
					$ntpStatus = "PASS"
					$logMessage = "vCenter appliance shell NTP configuration is good: $ntpConf and NTP server is reachable."
			} Else {
				$logMessage = "Photon OS NTP configuration is good: $ntpConf but NTP is NOT synchronized."
				$ntpStatus = "NOSYNC"
			}
		} Catch {
			$logMessage = "Unable to check timedatectl on Photon OS: $errorVar"
		}
	}
}

#Write-Output "ntpStatus: $ntpStatus logMessage: $logMessage "

If ( $ntpStatus -eq "FAIL" ) {
	Try {
		If ( $ipTarget -eq "10.0.0.10" ) {
			$ntpConfCmd = $ntpConfCmd.Replace('"','')
			$output = Invoke-Expression -Command $ntpConfCmd
		} Else {
			$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpConfCmd
			#Write-Host "ntpConfcmd output: $output"
		}
		$ntpConf = Choose-TimeSource $output
		If ( $ntpConf -Like "*server*") { 
			$ntpStatus = "PASS"
			$logMessage = "NTP configuration /etc/ntp.conf looks good: $output"
		}
		If ( $ntpConf -eq "invalid" ) { $logMessage = "NTP configuration /etc/ntp.conf is using an invalid time server: $output" }
		If ( $ntpConf -eq "notfound" ) { $logMessage = "NTP configuration /etc/ntp.conf is not found." }
	} Catch {
		#Write-Host "Catch:$hostNAme $ipTarget $uname $account"
		#Write-Host "Catch: output $output errorVar $errorVar"
		$logMessage = "NTP configuration /etc/ntp.conf is not found."
		$ntpConf = 'notfound'
	}
}

# try ntpq -p
If ( ($ntpConf -Like "*server*") -Or ( $ntpStatus -eq "FAIL" ) ) {
	Try {
		#Write-Host "remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpqCmd"
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpqCmd
		#Write-Host "ntpqCmd output $output"
		If ( $output -Like "*connection refused*" ) { 	
			$ntpqResult = "refused"
		} Else {
			$lines = $output.Split("`n")
			ForEach ( $line in $lines ) {
				# the only way to find a line with an asterisk
				If ( $line.IndexOf("`*") -eq 0 ) {
					$msg = $line
					Break
				}
			}
			If ( $msg -Like "*router*" -Or $msg -Like "*ntp*" -Or $msg -Like "10.0.100.1" -Or $msg -Like "*vcf*" ) {
				$logMessage = "NTP configuration looks good. $msg"
				$ntpStatus = "PASS" # We're done with NTP checks at this point
			}
		}
	} Catch {
		#Write-Output  "catch: errorVar $errorVar output $output"
		$ntpqError = $errorVar
	}
}

# if ntpqResult refused  or uname includes centos, try "chronyc sources" (default on CentOS)
If ( ($ntpqResult -eq "refused") -Or ($ntpConf -eq "notfound" -And $centOS) -Or ($ntpStatus -eq "FAIL" ) ) {
	Try {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpChronycCmd
		#Write-Output $output
		$chronycResult = Choose-TimeSource $output
		If ( $chronycResult -ne "invalid" -And $chronycResult -ne "notfound" ) {
			$ntpStatus = "PASS"
			If ( $ntpconf -ne "notfound" ) {
				$logMessage = "Chrony configuration looks good. $ntpConf and chronyc sources: $output"
			} Else {
				$logMessage = "Chrony configuration looks good. chronyc sources: $chronycResult"
			}
		}
	} Catch {
		#Write-Output "catch: $errorVar"
		$chronycError = $errorVar
	}
}

# if ntpSatus -eq FAIL and ntpConf -eq notfound - try timedatectl show-timesync
If ( $ntpConf -eq 'notfound' -Or $ntpStatus -eq 'FAIL' ) {
	#Write-Host "Attempting timedatectl show-timesync"
	Try {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpCmd3
		$timeDateCtlResult = Choose-TimeSource $output
		If ( $timeDateCtlResult -ne "invalid" -And $timeDateCtlResult -ne "notfound" ) {
			$logMessage = "Time configuration looks good. timedatectl show-timesync: $output"
			$ntpStatus = "PASS"
		}
	} Catch {
		$timeDateCtlError = $errorVar
	}
}

# Horizon engineering insists that identity-manager use VMware Tools timesync and not NTP
If ( $ntpStatus -eq 'FAIL' ) {
	#/usr/bin/vmware-toolbox-cmd timesync status
	Try {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpCmd4
		If ( $output -Like "*Enabled*" ) {
			$logMessage = "VMware Tools time sync is enabled"
			$ntpStatus = "PASS"
		}
	} Catch {
		If ( $errorVar ) {
			$toolboxError = $errorVar
		}
	}
}

# VCF Automation is different
If ( $ntpStatus -eq 'FAIL' ) {
	# 6/15/2020 vRA vracli ntp show-config
	Try {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $ntpCmd5
		$vraNtpResult = Choose-TimeSource $output
		If ( $vraNtpResult -ne "invalid" -And $vraNtpResult -ne "notfound" ) {
			$logMessage = "vRA time synch looks good. vracli ntp show-config: $output"
			$ntpStatus = "PASS"
		}
	} Catch {
		$vraError = $errorVar
	}
}

# if ntpConf invalid - /etc/ntp.conf found but server is set to invalid value

If ( $ntpStatus -eq "PASS" ) {
	Write-Logs "PASS" $target "NTP" "$hostname $logMessage"
} Else { # there is some manner of errror
	Write-Logs "FAIL" $target "NTP" "Time sync error on $hostName $logMessage"
}

# compare machine dateTime to local dateTime in UTC
Try {
	If ( $ipTarget -eq "10.0.0.10" ) { # there is no point in checking the Linux Main Console
		Exit
	} Else {
		$output = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $dateCmd
	}
	#$output = $output -replace ('\s+',",")
	If ( $output -Like "*Invalid*") {
		Write-Logs "FAIL" $target "Current Time" "Cannot get remote time on $hostName"
		Return
	}
	#Thu,30,Jul,2020,15:52:47
	($dow,$day,$month,,$year,$time) = $output.Split(',')
} Catch {
	Try {
		# if we're here, there was probably a remote error so try using the last element in $output
		($dow,$day,$month,,$year,$time) = $output[$output.Length - 1].Split(',')
	} Catch {
		Write-Logs "FAIL" $target "Current Time" "Cannot get remote time on $hostName $errorVar"
		Return
	}
}
		
If ( "$month/$day/$year" -ne "//" ) {
	$remoteUTC = [DateTime]"$month/$day/$year $time"
	$nowUTC = (Get-Date).ToUniversalTime()
	If ( $remoteUTC -gt $nowUTC ) {
		#Write-Host "remote UTC is ahead of local UTC time."
		$timeDiff = New-TimeSpan -Start $nowUTC -End $remoteUTC 
	} Else {
		#Write-Host "remote UTC is behind of local UTC time."
		$timeDiff = New-TimeSpan -Start $remoteUTC -End $nowUTC 
	}
}

If ( ($timeDiff -gt $timeTolerance)  ) {
	#Write-Host "$timeDiff is too much"
	$diff = $timeDiff.Seconds
	If ( $diff -gt 59 ) {
		Write-Logs "FAIL" $target "Current Time" "Time difference exceeds $tolSec second tolerance. localUTC: $nowUTC remoteUTC: $remoteUTC on $hostName"
	} Else {
		Write-Logs "WARN" $target "Current Time" "Time difference exceeds $tolSec second tolerance. localUTC: $nowUTC remoteUTC: $remoteUTC on $hostName"
	}	
} Else {
	#Write-Host "Time difference is ok"
	Write-Logs "PASS" $target "Current Time" "Time difference is ok on $hostName"
}
