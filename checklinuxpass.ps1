# 29-April 2024

# need this stuff at a minumum
# updated for LMC plink 20 January 2022
# 4/12/2022 accounting for core-a and core-b as INFO not FAIL and fixing this bug
# 8/22/2023 fixing the core-b test to be "-eq" and not "-ne"

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

#46 passwords set to NEVER expire
#51 vPodRouter root password not VMware1!

# need arguments
$hostName = $args[0]
$ipTarget = $args[1]
$account = $args[2]

$target = $hostname + "(" + $ipTarget + ")"

#Write-Host "checklinuxpass: $hostName $ipTarget $account"

<# Disabling this logic in 2021 - leaving vPodRouter unlocked in development
$vPodRouter = $false
If ( $ipTarget -like '*.*.*.1' ) {
	$vPodRouter = $true
	# Test-Connection labs.hol.vmware.com and set $wired = $true
	If ( Test-Connection labs.hol.vmware.com -Quiet ) {	$wired = $true 	}
}
#>

# create the chage command using "here" command syntax so Linux pipe can be sent literally
$chageCmd = @"
"chage -l root | grep -i password | grep -i expires | grep -vi warning"
"@

$errorVar = $null
$rootPassOkay = $false

$output = remoteLinuxCmdLMC $iptarget $linuxuser $password $chageCmd
$output | Set-Content "/tmp/output.txt"
$output = Get-Content "/tmp/output.txt"
ForEach ( $line in $output ) {
	If ( $line -Like "*Unknown command:*" ) {
		$errorVar = $line
	} ElseIf ( $line -Like "*xpires:*" ) {
		$errorVar = $line
	} ElseIf ( $line -Like "*Cloudbuilder*" ) {
		$erroVar = $line
	} ElseIf ( $line -Like "*never*" ) {
		$rootPassOkay = $true
	}
}

If ( $LASTEXITCODE -ne 0 ) { $errorVar = $output }

If ( $errorVar -ne $null ) {
	If ( ($hostname -Like "*core-a*") -Or ($hostname -Like "*core-b*") ) {
		Write-Logs "INFO" $target "root password aging" "Cannot check root password aging on $hostName"
	} Else {
		Write-Logs "FAIL" $target "root password aging" "Cannot check root password aging on $hostName Please check manually. $errorVar"
	}
} Else {
	If ( $rootPassOkay ) {
		Write-Logs "PASS" $target "root password aging" "Root password aging good on $hostName"
	} Else {
		If ( ($hostname -Like "*core-a*") -Or ($hostname -Like "*core-b*") ) {
			Write-Logs "INFO" $target "root password aging" "No chage command so cannot check root password aging on $hostName"
		} Else {
			Write-Logs "FAIL" $target "root password aging" "Root password expires on $hostName $output"
		}
	}
}

# check account specified in PuTTY session or otherwise on command line
$accountPassOkay = $false

If ($account -ne "root" ) {
	$errorVar = $null
	$chageCmd = @"
"chage -l $account | grep -i password | grep -i expires | grep -vi warning"
"@
	$output = remoteLinuxCmdLMC $iptarget $account $password $chageCmd
	If ( $LASTEXITCODE -ne 0 ) { $errorVar = $output }
	
	$output | Set-Content "/tmp/output.txt"
	$output = Get-Content "/tmp/output.txt"
	ForEach ( $line in $output ) {
		#Write-Host $line
		If ( $line -Like "*Unknown command:*" ) {
			$errorVar = $line
		} ElseIf ( $line -Like "*xpires:*" ) {
			$errorVar = $line
		} ElseIf ( $line -Like "*never*" ) {
			$accountPassOkay = $true
		}
	}
	
	If ($accountPassOkay) {
		Write-Logs "PASS" $target "$account password aging" "$account password aging good on $hostName"
	} Else {
		If ( ($hostname -Like "*core-a*") -Or ($hostname -Like "*core-b*") ) {
			Write-Logs "INFO" $target "$account password aging" "No chage command so cannot check root password aging on $hostName"
		} Else {
			Write-Logs "FAIL" $target "$account password aging" "$account password expires on $hostName $errorVar"
		}
	}
}
