# 05-May 2024

# required in order to pass by reference
$result = ""

$autocheckModulePath = Join-Path -Path "$PSSCriptRoot" -ChildPath "autocheckfunctions.psm1"
If ( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else { 
	Write-Output "PSSCriptRoot: $PSSCriptRoot Cannot find AutoCheckfunctions.psm1. Abort."
	Exit
}
$linuxMachines = @{}
$Layer2Linux = @{}

# BEGIN HERE


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