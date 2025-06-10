# 07/24/2021
# updated for LMC plink

# need this stuff at a minumum

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
$kernel = $args[2]

$target = $hostname + "(" + $ipTarget + ")"


# create the chage command using "here" command syntax so Linux pipe can be sent literally
If ( $kernel -Like "*SUSE*" ) {
	# "Copyright (c) 2014 VMware, Inc." appears to identify a VMware SUSE appliance reliably on vrli, vrops, vra, vro and vr
	#$checkCmd = 'grep "Copyright (c) 2014 VMware, Inc." /etc/init.d/*' # cannot get double quotes to pass through to bash
	$checkCmd = "test -d /opt/vmware \; echo $?"
	$tf = "TF"
}
If ( $kernel -Like "*CentOS*" -Or $kernel -Like "*Red*Hat*" ) { # is it RedHat or CentOS?
	$checkCmd = 'cat /etc/redhat-release'
}

$errorVar = $null
$output = remoteLinuxCmdLMC $ipTarget $linuxuser $linuxpassword $checkCmd

#Write-Output "output: $output"
If ( $errorVar ) {
	Write-Logs "FAIL" $target "kernel check" "Cannot check kernel on $hostName $errorVar"
} 
If ( $kernel -Like "*SUSE*" ) {
	If ($output -eq $true) {
		Write-Logs "PASS" $target "kernel check" "SUSE kernel is okay on VMware appliance $hostName"
	} Else {
		Write-Logs "FAIL" $target "kernel check" "SUSE kernel must NOT be used on non-VMware appliance $hostName"
	}
}
If ( $kernel -Like "*CentOS*" -Or $kernel -Like "*Red*Hat*" ) {
	If ( $output -like "*CentOS*" ) {
		Write-Logs "PASS" $target "kernel check" "CentOS kernel is okay on $hostName"
	} Else {
		Write-Logs "FAIL" $target "kernel check" "RedHat kernel must NOT be used on $hostName"
	}
}
