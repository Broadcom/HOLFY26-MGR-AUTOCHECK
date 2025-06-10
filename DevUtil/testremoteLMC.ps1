# 5/20/2021 testing

$autocheckModulePath = "$PSSCriptRoot/../autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Host "Abort."
}

<# uname command
$ipTarget = "192.168.110.1"
$account = "root"
$unameCmd = "uname -a"
[Array]$raw = remoteLinuxCmdLMC $iptarget $linuxuser $password $unameCmd
Write-Host "uname: $raw[0]"
#>

#<# ntpd test
$ipTarget = "192.168.100.1"
$account = "root"
$ntpdTest = @"
"ps -ef | grep ntpd| grep -v grep"
"@
$output = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $ntpdTest
If ( $output -NotLike "*/usr/sbin/ntpd*" ) { $output = "BAD" }
Write-Host "output: $output"
If (  $output -eq "BAD" ) {
	Write-Host "Need to start ntpd"
}
#>

<# VMware appliance check
$errorVar = ""
$ipTarget = "192.168.110.1"
$account = "root"
$checkCmd = @"
"test -d /opt/vmware && echo True || echo False"
"@
$raw = remoteLinuxCmdLMC $ipTarget $account $linuxpassword $checkCmd
Write-Output "appliance result: $raw $errorVar"
#>

<# NSX Manager check
$ipTarget = "192.168.110.40"
$account = "root"
$nsxt = $True
$hostName = "nsx-mgr.corp.local"
$nsxTuser = "admin"
$pwCmd = "get user $nsxTuser password-expiration"
$raw = remoteLinuxCmdLMC $hostName $nsxuser "sword:" $nsxpassword $pwCmd $nsxt
#>

<# vCD check
$ipTarget = "192.168.110.40"
$account = "root"
$checkCmd = @"
"test -f  /opt/vmware/vcloud-director/bin/vmware-vcd-cell && echo True || echo False"
"@
$raw = remoteLinuxCmdLMC $ipTarget $linuxuser "sword:" $linuxpassword $checkCmd
$output = getCmdOutputLMC $checkCmd $raw "TF"
Write-Host "output: $output"
#>

<# Time check
$ipTarget = "192.168.110.1"
$account = "root"
$photonConfCmd  = @"
"grep ^NTP /etc/systemd/timesyncd.conf"
"@
$ntpCmd3a = @"
"timedatectl | grep ^NTP | cut -f2 -d':'"
"@
$ntpConfCmd = @"
"grep ^server /etc/ntp.conf"
"@
$dateCmd = 'date -u +%a,%d,%b,%Y,%H:%M:%S'
$raw = remoteLinuxCmdLMC $ipTarget $linuxuser "sword:" $linuxpassword $dateCmd
$output = getCmdOutputLMC $dateCmd $raw
Write-Host $output
#$ntpConf = Choose-TimeSource $output
#Write-Host $ntpConf
#>

<# check for SSH Auth (no password)
$ipTarget = "192.168.110.22"
$account = "root"
$errorVar = $null
# if using a bogus password works then ssh auth is enbabled.
$raw = testsshauthLMC $ipTarget $account "sword:" "bogus" "ls"
If ( $raw -Like "*sshauth: FALSE" ) { 
	$errorVar = "FALSE"
} Else { $errorVar = $null }
If ( $errorVar -ne $null ) {
	Write-Host "WARN"
} Else {
	Write-Host "PASS"
}
Write-Host "raw: $raw"
#>

<# check for SUSE and Red Hat
$ipTarget = "192.168.110.100"
$account = "root"
#$checkCmd = "test -d /opt/vmware ; echo $?" # SUSE
#$tf = "TF"
$checkCmd = 'cat /etc/redhat-release'
$errorVar = $null
$raw = remoteLinuxCmdLMC $ipTarget $linuxuser "sword:" $linuxpassword $checkCmd
$output = getCmdOutputLMC $checkCmd $raw $tf
Write-Host "output: $output"
#>

<# check password expiration
$hostName = "ivcsa.corp.local"
$ipTarget = "192.168.110.22"
$account = "root"

$chageCmd = @"
"chage -l $account | grep -i password | grep -i expires | grep -vi warning"
"@

$raw = remoteLinuxCmdLMC $iptarget $linuxuser $password $chageCmd
If ( $raw -Like "*exit*" ) { # identity-manager SUSE is weird
	ForEach ( $line in $raw ) {
		If ( $line -Like "*xpires:*" ) { 
			$output = $line 
			Break
		}
	}
}
Write-Host "output: $output"
#>

<# check that EXT file systems are disabled
$hostName = "vcsa-01a.corp.local"
$ipTarget = "192.168.110.22"

#$hostName = "identity-manager.corp.local"
#$ipTarget = "192.168.110.77"

$fsCmd = @"
"mount | grep ext[234] | cut -f 1 -d ' '"
"@


[Array]$raw = remoteLinuxCmdLMC $ipTarget $linuxuser $linuxpassword $fsCmd
ForEach ( $line in $raw ) {	
	If ( $line.StartsWith('/d') ) { 
		#Write-Output "line: $line"
		$output += "$line "
	}
}
#Write-Output "output: $output"

If ( $output -eq $null ) {
	$continue = $false # nothing to check
	Write-Host "PASS" $ipTarget "EXT FS" "No file systems to check on $hostName"
}

#$output = "/dev/sda3"

$fsToCheck = $output.split(' ')
$output = $null
#Write-Output "fsToCheck: $fsToCheck"
ForEach ($fs in $fsToCheck) {
	$fsCmd2 = @"
"dumpe2fs $fs 2>&1 | grep -v dumpe2fs | grep ^Maximum; dumpe2fs $fs 2>&1 | grep -v dumpe2fs | grep -i interval"
"@
	#Write-Host "fsCmd2: $fsCmd2"
	[Array]$raw = remoteLinuxCmdLMC $ipTarget $linuxuser $linuxpassword $fsCmd2
	ForEach ( $line in $raw ) {
		If ( $line -Like "Maximum mount count:*" ) { $output += "$line " }
		If ( $line -Like "*check interval:*" ) { $output += "$line " }
	}
}
Write-Host "output: $output"

#>

<# getrules.sh from router
$ipTarget = '192.168.110.1'
$ipTarget = 'router.corp.local'

$getrulesCmd = @"
"head -3 /root/getrules.sh | sed s/@//g | sed s/,//g | sed s/\#//g | sed s/PST//g"
"@

[Array]$raw = remoteLinuxCmdLMC $iptarget $linuxuser $password $getrulesCmd
#Write-Output $raw
If ( $raw[0] -eq "DENIED" ) {
	Write-Output "Cannot check $ipTarget possibly due to non-standard root password. Please check manually."
} Else {
	$dateString = $raw[2]
}
Write-Output "dateString: $dateString"
#>

<# checksum on getrules.sh on router
$iptarget = '192.168.110.1'
$getrulesChecksumRef = "332695623"
$grCKsumCmd = @"
"cksum /root/getrules.sh | cut -f1 -d' '"
"@
$raw = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $grCKsumCmd
($junk, $grCKsum) = $raw.Split()
Write-Output "checksum: $grCKsum"
#>

<# get /root/version.txt if it exists
$iptarget = '192.168.110.1'
$verCmd = @"
"if [ -f /root/version.txt ] ; then ls -l /root/version.txt ; cat /root/version.txt ; else echo 0 ; fi"
"@
$raw = remoteLinuxCmdLMC $iptarget $linuxuser $linuxpassword $verCmd
$rtrVer = $raw
Write-Output "rtrver: $rtrVer"
#>

<# testing scpLMC
$routerSource = 'router.corp.local:/home/holuser/running_config/*'
$localDest = Join-Path -Path $logDir -ChildPath "vPodRouter"
If ( Test-Path $localDest) {
	Remove-Item -Path $localDest -Recurse -Force 
} 
New-Item -Path $localDest -ItemType Directory -ErrorAction 0 | Out-Null

$output = scpLMC "holuser@$routerSource" $localDest $linuxpassword
#>

<# test ssh auth
#$ipTarget = "192.168.120.209" # 2140 chi-client-02 should FAIL
$ipTarget = "192.168.110.22" # vcsa-01a should PASS
$raw = testsshauthLMC $ipTarget $linuxuser "sword:" "bogus" "ls"
If ( $raw -Like "*sshauth: FALSE" ) { $errorVar = "FAIL" }
Write-Output "$raw errorVar: $errorVar"
#>


$ctr = 0
ForEach ( $line in $raw ) {
	Write-Host "$ctr $line"
	If ( $line -Like "*exit*" ) { $output = $raw[$ctr+2] }
	If ( $line -eq "True" -Or $line -eq "False" ) { $output = $line }
	$ctr++
}
#$output = $raw[10]
If ( $LASTEXITCODE -ne 0 ) {
	Write-Host "ERROR: $output $LASTEXITCODE"
} Else {
	Write-Host "SUCCESS: $output"
}
# restore the PuTTY cached host keys file
$sshhostkeys = '/home/holuser/.putty/sshhostkeys'
$tmpsshhostkeys = '/home/holuser/.putty/NOTsshhostkeys'
Move-Item -Path $tmpsshhostkeys -Destination $sshhostkeys
