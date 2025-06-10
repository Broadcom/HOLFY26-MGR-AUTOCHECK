# AutoCheck.ps1 - 30-May 2025
$version = "1.5.2"
<#

.SYNOPSIS			This script is intended to check VMware Hands-on Labs vPods.

.DESCRIPTION		Attempt to check most items on the HOL Report Card v2.xlsx.

.NOTES				Requires PowerCLI, autocheckFunctions.psm1 and numerous scripts

.EXAMPLE			pwsh -File autocheck.ps1

.INPUTS				vApp name from vAppName.txt
					Layer one inventory from LayerOneInventory.txt
					config.ini in /vpodrepo

.OUTPUTS			Output folder is /tmp/AutoCheck
					Pass/Fail output is written to vPod-Version.CSV log file
					Detailed output is written to autocheck-detail-<vPod Name>.csv  file
					Inventory utilization to vPod-Version-invutilrpt.txt
					Web page autocheck-detail-<vPod Name>.html and HTML sub-folder
					
Autocheck at this point “should” catch the following on layer 1 and layer 2 machines:

Not in the report card checks but HOL conventions are checked:

Browser bookmarks listed in the config.ini (meaning labstartup.py will check them.)
PuTTY sessions using account@host convention

These are no longer implemented since a manual run will never see these issues:
	Shutdown Event Tracker window (improper shutdown of Main Console)
	Improper shutdown of Chrome browser

Report Card checks implemented:

#3 non-standard passwords (multiple FAIL checks with “Cannot check” messages)
#4 vPod was created from approved templates - copy version.txt to $logDir
#10 SSL Certs valid
#11 SSL Certs expiration
#12 vCenters reachable
#13 vSphere license expiration
#14 No vCenter or vSphere Eval licenses
#15 NTP configured on ESXi hosts
#16 L2 VMs uuid.action = keep
#17 L2 Linux TypeDelay
#18 L2 VMs no CPU/Mem reservations or limits
#19 No labStartup.log errors - copy LabStartup.log to $logDir
#20 Custom labstartup script(s) working as expected - copy LabStartup.ps1 to $logDir
#21 All internal & external URLs are reachable (partial: getting bookmarks for #10 and #11)
#22 SSL Certs validate correctly (not sure how this is different from #10 and #11)
#23 All Windows OS firewalls disabled
#24 vPodRouter iptables firewall working as expected - Doug to make accessible to holuser
#25 vPodRouter Proxy working as expected - Doug to make accessible to holuser (check Windows Internet proxy setting)
#29 Windows OS license ID changed from default - exclude Main Console (actually just checking for activation)
#30 No SLES or RedHat VMs (unless VMware appliances)
#31 Static IPs on ALL VMs (also checking DNS)
#32 Use VMXNET3 adpater on all Windows 2012 VMs
#33 Disable fsck of ext file systems
#35 Storage policy not impacting I/O (flag for manual review)
#37 DRS set to Partial or Off - not Full or Manual
#38 vSphere HA Disabled (unless required for demo)
#39 If using VSAN, Explicit HDD and SSD flags configured (at least I believe I can check)
#40 Browser history & cache cleared (well - at least history only contains lab URLs - not sure about cache)
#43 Check for updates: Never (Windows task Google check for updates disabled)
#44 Plugins: Allow all (and remember)
#45 Google Chrome "Do not send data" settings
#46 passwords set to NEVER expire including NSX-T (default is 90-day expiration)
#47 PuTTY entry for all Linix VMs: no password prompt
#48 SSH AUTH for passwordless login
#50 no PuTTY session for vPodRouter
#51 vPodRouter root password not VMware1! - policy change 2020 ONLY if deployed by VLP (irrelevant for AutoCheck)
#52 VMs syncd to ntp.$dom or Main Console (also checking time difference)
#56 Desktop Background (updated 6/29/2020)
#57 Recycle Bin empty
#58 Temp directory contains no large files (total size <10 MB)
#59 Removed temporary storage / scratch disk
#60 Remove stray files: installers, downloads
#61 README.TXT is complete, no spelling mistakes - check README.txt changed and copy to $logDir
#62 Desktop shortcut names not truncated
#64 Main Console screen resolution = 1024 x 768
# 2/5/2020 increasing default screen resolution to 1280 x 800
#65 Include skipRestart utility if Win7/2K3/2k8
#66 vCloud Director storage leases never expire (Mike D. helped)

# PARTIAL:
#27 All VMware products licensed and will not expire before $licenseExpireDate (vCD, vRA, vROPs and NTX-T implemented)

# tough to automate checks:

#26 vRO licensed correctly (if installed) - able to detect but not check licensing
#28 3rd party licenses will not expire before 12/31/2019
#34 vMotion or storage vMotion without I/O issues
#36 Cloning or creating templates with low I/O
#41 Chrome toolbar shortcuts organized, not truncated, legible
#42 Unused links on Chrome toolbar removed
#53 Callback sent from VLP tested ok
#54 Callback server script or webpage working as expected
#55 Student Checkin, Cleanup and Dashboard working as expected
#63 Window dimensions correct: not off screen, no weirdly wrapping text
#67 Horizon broker tunnel SSL Certificate will not expire

#>

# updated for vSphere 7 Storage Profile checks #35
# updated PuTTY session checks 4/17/2020
# updated PuTTY no session check to INFO from FAIL 4/18/2020
# flush the iDISK volume to ensure all writes are complete 5/1/2020
# deal with Horizon or other possible issues creating windows snapshots and changing power state. 5/28/2020
# running 2151 and two "DELETE" L2 Windows machines with no IP were not handled properly. Need to revisit later.
# checking vPodRouterHOL for UTC time zone and /root/version.txt 6/4/2020 (moved to checkCoreTeamTools.ps1 1/21/2021
# added more IP patterns better logic for choosing the IP address to set as $ipTarget (key for machine hash) 6/12/2020
# corrected default screen resolution PASS message
# added even more IP patterns. converted vm.Guest.IPAdress to array for Choose-IP 6/13/2020
# updated checkLinuxTime.ps1 added support for more ways to perform NTP checks (timedatectl show-timesync and vracli)
# added Main Console Registry check for time zone fix 6/17/2020
# L1 Linux and Windows best to check reverse DNS first in case vCD name is different 6/18/2020
# L2 Linux and Windows with no guest IP address ignored. Check manually. 6/18/2020
# VMworld 2020 Main Console desktop background wallpaper updated 6/29/2020
# holding off on the new HOL branding change 6/30/2020
# more updates to DNS checking and IP ranges after checking 2182 6/30/2020
# check for duplicate DNS entries for same IP address 2126 7/2/2020
# major update to DNS verification and minor update to checkLinuxTime 7/4/2020
# added ntpd check on router plus a complete re-write of checkLinuxTime and minor L2 DNS logic update if no IP 7/14/2020
# implemented checkCoreTeamTools.ps1 including new function in AutoCheckFunctions. 7/16/2020
# fixing the incomplete line for the vPodRouterHOL in LayerOneInventory.txt 07/16/2020
# corrected logic in Choose-IP (again) changed DHCP and SSH AUTH to WARN instead of FAIL
# doubled the $ipCtr to wait longer for L2 IP address from Tools 7/23/2020
# more logic changes to L2 VM IP and DNS IP resolution
# corrected L2 VM name to use and added commands to get bundle files from router 06/08/2020
# moved repetitive L2 code to functions to make it easier to maintain 17/08/2020
# added logic for L2 NAT 08/18/2020
# corrected snapshot bug 08/19/2020
# corrected bugs added WARN for no response pattern in URLs.txt 08/20/2020
# added FreeNAS iSCIS (VMFS) check in C:\hol\Datastores.txt for LabStartup checking 08/24/2020
# made allowances for HCX "VMware Mobile Platform" and fixed a few bugs. 08/26/2020
# added detail CSV file to include detail from log file 08/26/2020
# added vRealize Automation license check 08/27/2020
# updated NSX hostname match to be "*nsx*" 08/28/2020
# added NSX hostname match to also be "*csm*" (2122) and "*edge*" (2121) 08/31/2020
# check-NSX-T.ps1 now checking password expiration for admin, root and audit 08/31/2020
# checkvROPs.ps1 added to check vROPS license expiration 09/01/2020
# updated checkNSX-T.ps1 to check license expiration 09/03/2020
# added ESXi version and build check to warn if non-standard HOL version 01/10/2020
# added check for dissimilar ESXi builds in the vPod 10/8/2020
# added ready time check: PASS < 30, WARN < 45 and FAIL > 45 10/8/2020
# fixed bug line 1764 fwctr re-initialized inside the while loop. moved to before the loop. 11/12/2020
# fixed bug line 194 $rTime = [int]$f[7] # must cast to int 11/13/2020
# vRO standalone appliance has vracli but no license 11/30/2020
# checking DNS forwarders 01/19/2021
# enhanced time sync checks for Photon and CentOS 01/24/2021
# changed CPU/Memory reservations/shares from FAIL to WARN 01/24/2021
# updated LabStartup.ps1 date 01/25/2021
# moved Desktop wallpaper and vPodRouter checks to checkCoreTeamTools.ps1 01/29/2021
# added postProcCSV.ps1 to generate static HTML if the iDISK is not present 02/05/2021
# refinements to postProcCSV.ps1 to correct some generated HTML 02/09/2021
# further refinements to postProcCSV.ps1 to process bare lines with lists of files 02/10/2021
# begin version 1.3 to support Linux PowerShell/PowerCLI on LMC. added remoteLinuxCmdLMC function for Linux expect 03/06/2021
# updates for 2021 development 03/10/2021
# support for iDisk in Linux 03/15/2021
# need lowercase file names in Linux thanks to ISO 9660 CD format 03/17/2021
# corrected issues in postproccsv.ps1 due to Linux and enhancement to create empty detail files if needed. 03/17/2021
# if no vCenters don't check datastores 03/18/2021
# prep-idisk.sh creates 2 partitions to match the Windows. idisksrv mounts the 2nd partition to retrieve the AutoCheck zip 03/22/2021
# added html.zip for completeness 03/23/2021
# unmounting /mnt/idisk as part of endAutoCheck function 03/23/2021
# adjusting prep-idisk.sh to use block range that UDEV expects on idisksrv
# updates for 2021 dev cycle - build numbers, license expirations and hash values
# corrected generated HTML for success, updated dates and hashes again for LabStartup.ps1 and LabStartupFunctions.psm1 04/05/2021
# added new default storage policy in vSphere 7.0 Update 2 04/06/2021
# implemented recycle bin checking for LMC 04/07/2021
# moved Windows scratch drive test to functions and added Linux check scratch drive test 04/11/2021
# added several more checks to the LMC. #58, #60, #61, #19, #20 and #4 04/12/2021
# added Firefox privacy checks (do not send data, do not run studies, do not send crash reports) 04/13/2021
# added Internet proxy checks and populate/retrieve ~holuser/running_config files 04/14/2021
# numerous updates to support Firefox browser and Internet settings on the LMC 04/16/2021
# some bug fixes to checkLinuxScratchDrive, checkurls.ps1 and testsslcert.py 04/17/2021
# minor updates to verify vSphere checks work on LMC. 04/19/2021
# better error handling checking ESXi claim rules 04/19/2021
# Linux L1, L2, DNS and PuTTY checks for LMC 04/20/2021
# updated checkurls.ps1 to use testsslcert.py for Windows if Python present. Fixed premature exit in checkcoreteamtools.ps1 4/26/2021
# backing out the switch to testsslcert.py since standard WMC does NOT have pyopenssl module. 4/26/2021
# past the VMware appliances checks for now. Added function getCmdOutputLMC for single line command output 4/28/2021
# implemented checklinuxtime.ps1 for use on LMC. More testing needed. 4/30/2021
# implemented ssh auth checking for use on LMC. 5/5/2021
# implemented verify ssh root access and checklinuxrh-suse.ps1 on LMC 5/11/2021
# optional resources files bundle feature - updates to LabStartup, LabStartupFunctions and LabUpdater for hybrid labs. 5/18/2021
# implemented Linux password checking for LMC 5/19/2021
# implemented Linux EXT FS checking disabled for LMC 5/20/2021
# implemented Main Console display resolution checking on LMC 5/24/2021
# implemented inventory utilitization report generation on LMC except L1 Windows 5/28/2021
# syncing up version with AutoCheck ISO name in HOL-Dev 5/28/2021
# lsfunctions.py update to fix Firefox cleanup bug 6/4/2021
# ignoring all vCLS L2 VMs. 6/10/2021
# ignoring all SupervisorControlPlaneVM L2 VMs 6/14/2021
# optional hash for LabStartupFunctions if test_url.py is present 6/24/2021
# many changes releated to implementing plink in place of expect (testsshauth exception) 7/25/2021
# prep-idisk.sh update to check for mounted /mnt/idisk and return success (issue with 2237) 7/25/2021
# added check for BuildChecklist.txt NOT on the desktop 7/26/2021
# better vRA detection, bugs fixed in checkurls.ps1 7/27/2021
# PowerShell change in Test-Connection (-ComputerName for v5 or earlier and -TargetName for v6 or higher) 7/29/2021FAIL
# if PowerShell Test-Connection fails, try ping to be certain before skipping. 09/03/2021 
# change to $dom instead of hard-coded domain name
# bug fixes related to domain name change
# updates to getPuTTYhostkey() and checkurls.ps1 1/24/2022
# added check for leftover manual AutoCheck files that need to be removed 1/25/2021
# fixed bug with Test-Connection parameter version 6 or greater not version 5 or greater 1/27/2022
# ignore 192.168.0.2 that autocheckdeploy puts in the layeroneinventory for the pfrouterHOL 2/1/2022
# calculate the expiration date based on $vPodName
# updating license expiration and SSL cert calculation baded on coop ID instead of the licenseexpiration.txt file
# fixing IP address for the router (again) since vCD returns stupid values.
# determine default browser on Windows and run appropriate checks 4/12/2022
# changes to autocheckfunctions.psm1 check default browser if Windows only and checkurls argument is now $vPodYear not $labYear 6/20/2022
# linux display not available so use ~holuser/.config/monitors.xml width and height 6/20/2022
# fixed ping bug if running on Linux 6/22/2022
# updates to autocheckfunctions, checkcoreteamtools and checkurls 6/24/2022
# updates to autocheckfunctions and checkcoreteamtools - verify vpod_sku in labstartup and correct version date processing
# minor bug fixes
# ignore the Manager VM, WARN for DNS/PuTTY 2/16/2023
# checking for tools.guest.desktop.autolock on Windows L2 VMs 2/19/2023
# checking for VMRC lock fix in LabStartup.ps1 5/31/2023
# replace corp.local with corp.vmbeans.com and update lsfunctions.py hash 6/2/2023
# updates to labStartupFunctions.psm1 hash, checklinuxtime, checklinuxextfs and checkWindowsActivation 6/4/2023
# added wildcard to google scheduled task in checkWindowsChromeUpdates.ps1
# more updates to checkWindowsChromeUpdates.ps1, another WARN for DNS lookup if no IP 6/11/2023
# better error checking if snapshot could not be created 6/12/2023
# changing HA and DRS settings to WARN instead of FAIL 6/12/2023

Write-Output "AutoCheck.ps1 version $version"

$autocheckModulePath = Join-Path -Path "$PSSCriptRoot" -ChildPath "autocheckfunctions.psm1"
If ( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else { 
	Write-Output "PSSCriptRoot: $PSSCriptRoot Cannot find AutoCheckfunctions.psm1. Abort."
	Exit
}

If ( -Not ( Test-Path $vAppNameFile ) ) {
	Write-Output "You must create ${vAppNameFile}. Exit."
	Exit 1
}

If ( -Not ( Test-Path $layerOneInfo) ) {
	Write-Output "$layerOneInfo file not found. Exit."
	Exit 1
}

If ( $vPodName -eq "HOL-BADSKU" ) {
	Write-Output "Please update $vAppNameFile to the correct name of the vPod Template and NOT $vPodName"
	Write-Output "Please confirm the contents of $layerOneInfo accurately lists L1 VMs in VCD."
	Exit 1
}

#$result must be created in order to pass as reference for looping
$result = ''
 
##############################################################################
##### BEGIN HERE
##############################################################################

Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $csvDetailFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file

# include the LayerOneInventory.txt file in the output bundle
$layerOneCopy = Join-Path $logDir "LayerOneInventory.txt"
Copy-Item $layerOneInfo $layerOneCopy

Write-Output "Checking vPod ready status..."
$status = Get-Content -Path $statusFile
If ( ($status -like '*Ready*')  -And ( $status -NotLike "*Not Ready*") ) {
	Write-Logs "PASS" "LabStartup" "Ready status" $status
} Else {
	Write-Logs "FAIL" "LabStartup" "Ready status" $status # actually if not ready, AutoCheck will not even run.
}

# log actual ready time
$startlogPath = Join-Path -Path $labStartupRoot -ChildPath "labstartup.log"
$startLog = Get-Content -Path $startlogPath

Foreach ( $line in $startLog ) {
	If ( $line.Contains("LabStartup Finished - ") ) {
		#Write-Output $line
		$f = $line.Split()
		$rTime = [int]$f[7] # must cast to int. fixed 11/13/2020
		If ( $rTime -le 30 ) {
			Write-Logs "PASS" "LabStartup" "Ready time" "Ready time is $rTime minutes which is good."
		} ElseIf ( $rTime -le 45 ) {		
			Write-Logs "WARN" "LabStartup" "Ready time" "Ready time is $rTime minutes which is longer than the standard 30 minutes."
		} Else {		
			Write-Logs "FAIL" "LabStartup" "Ready time" "Ready time is $rTime minutes which is much longer than the standard 30 minutes."
		}
		Break # we want the first ready time only (no LabCheck entries
	}
}

# check vPod naming convention
If ( $vPodName -Match "HOL-\d\d\d\d-v0\.\d+$" ) {
	Write-Logs "PASS" "vPod Name" "HOL Naming Convention" "Thank you for using the correct vPod naming convention. Core Team automation will work as expected."
} Else {
	Write-Logs "FAIL" "vPod Name" "HOL Naming Convention" "Core Team automation will not work on $vPodName Please use HOL-####-v0.# convention only."
}

#56 Desktop Background moved to checkCoreTeamTools.ps1 1/29/2021

# check Core Team files
Invoke-Expression "pwsh -File $PSScriptRoot/checkcoreteamtools.ps1"

# check the Main Console
Invoke-Expression "pwsh -File $PSScriptRoot/checkconsole.ps1"

Write-Output "Checking web browser and Internet proxy settings..."
#45 Google Chrome "Do not send data" settings
#44 Plugins: Allow all (and remember) - actually the best we can do with Chrome now is "Ask" and not "Block"

Copy-Item -Path $PSSCriptRoot/checkbrowsers.ps1 -Destination $mcTmp/checkbrowsers.ps1
If ( $WMC ) {
	$quiet = RunWinCmd "pwsh -File C:\hol\checkbrowsers.ps1" ([REF]$result) 'console' 'Administrator' $password
} ElseIf ( $LMC ) {
	# copy again using Linux command
	Invoke-Expression "cp /home/holuser/autocheck/checkbrowsers.ps1 /lmchol/tmp/checkbrowsers.ps1"
	remoteLinuxCmdLMC "console" "holuser" $password "pwsh -File /tmp/checkbrowsers.ps1"
	$internetSettingsCmd = "gsettings list-recursively org.gnome.system.proxy"
	$internetSettings = Invoke-Expression "sshpass -p $password ssh holuser@console $internetSettingsCmd"
	ForEach ( $setting in $internetSettings ) {
		If ( $setting -Like "*org.gnome.system.proxy mode*" ) {
		  ($p, $k, $proxyEnabled) = $setting.Split()
		}
		If ( $setting -Like "*org.gnome.system.proxy.https host*" ) { 
		  ($p, $k, $proxyServer) = $setting.Split()
		}
	}
	Write-Logs "INFO" "Proxy" "Proxy System Settings" "proxyEnabled: $proxyEnabled proxyServer: $proxyServer"
}

# copy the checkbrowsers.txt file to local then process. bug with Test-Path over NFS.
Invoke-Expression "cp $mcTmp/checkbrowsers.txt /tmp/checkbrowsers.txt"
While ( -not ( Test-Path -Path "/tmp/checkbrowsers.txt" ) ) {
        Write-Output "Waiting for /tmp/checkbrowsers.txt..."
	Start-Sleep -Seconds 5
}
ForEach ( $line in Get-Content -Path "/tmp/checkbrowsers.txt" ) {
	$line = $line.Trim()
	$scratchFields = $line.Split('~')
	Write-Logs $scratchFields[0] $scratchFields[1] $scratchFields[2] $scratchFields[3]
}
#Remove-Item "$mctmp/checkbrowsers.ps1"
#Remove-Item "$mctmp/checkbrowsers.txt"

##############################################################################
##### Check Browser Bookmarks against URLs.txt
##############################################################################
# Robust lab startup scripts (Are bookmarks in URLs.txt?)

##############################################################################
##### Check SSL Certificates Expiration
##############################################################################

#10 SSL Certs valid
#11 SSL Certs expiration
#40 Browser history & cache cleared (well - at least history only contains lab URLs - not sure about cache)

Invoke-Expression "pwsh -File $PSScriptRoot/checkurls.ps1"


##############################################################################
##### Check vSphere
##############################################################################

# Report card #4 vPod was created from approved templates (check vCenter and ESXi builds)
# Report card #12 vCenters reachable
# Robust lab startup scripts (Are FreeNAS iSCSI datastores in config.ini?)
# Report card #13 vSphere license expiration
# Report card #14 No vCenter or vSphere Eval licenses
# Report Card #15 NTP configured on ESXi hosts
# Report Card #16 L2 VMs uuid.action = keep
# Report Card #17 L2 Linux TypeDelay
# Report UUID.action setting on vVMs
# Report typematic delay for Linux machines only	
# Report autolock setting... for Windows machines only
# Report card #18 L2 VMs no CPU/Mem reservations or limits
# Report card #35 Storage policy not impacting I/O (flag for manual review)
# Report card #37 DRS set to Partial or Off - not Full or Manual
# Report card #38 vSphere HA Disabled (unless required for demo)
# Report card #39 If using VSAN, Explicit HDD and SSD flags configured

Invoke-Expression "pwsh -File $PSScriptRoot/checkvsphere.ps1"

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
	If ( $name -Like "*console*" ) { Continue } # do not check the Main Console
	If ( $name -Like "*stg*-01a*" ) { Continue } # do not check the FreeNAS storage appliance
	If ( $name -Like "*router*" ) { Continue } # do not check the vpodrouter
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ($name -like '*router*') { # The router is special
		$name = 'router'
		$ipAddress = '10.1.10.129'
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
	If ( $hostName -Like "*esx*" -or $hostName -Like "*vcenter*" ) {
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
				Invoke-Expression "pwsh -File $checkvROPs $hostName $ipTarget $apiVersion"
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
	##### Check Linux time ( use account and standard password )
	##### Report card #52 VMs syncd to ntp.site-a.vcf.lab, router.site-a.vcf.lab, 10.1.1.1 or 10.1.10.129
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
			Invoke-Expression "pwsh -File $timeCheck `"$hostName`" $ipTarget $uname $account"
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
		Invoke-Expression "pwsh -File $redHatSUSEscript `"$hostName`" $ipTarget `"$os`""
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
	Invoke-Expression "pwsh -File $clpScript `"$hostName`" $ipTarget $account"

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
	Invoke-Expression "pwsh -File $clEXTFS `"$hostName`" $ipTarget"
	
	#### End Check Linux EXT file systems
	
	# if we powered on the machine, power it off
	If ($linuxMachines[$ipTarget].Off) { 
		Write-Output "End of Linux checks for $hostName. Powering off $hostName..."
		restorePowerState $name $linuxMachines[$ipTarget].Off
	}

} # END Linux checks loop

# remove the bad/powered off machines - no further testing
Foreach ($ipTarget in $removeMachines) {
	$linuxMachines.Remove($ipTarget)
	If ( $Layer1Linux[$ipTarget] ) { $Layer1Linux.Remove($ipTarget) }
	If ( $Layer2Linux[$ipTarget] ) { $Layer2Linux.Remove($ipTarget) }
	
	$name = $linuxMachines[$ipTarget].Name
	If ( $name -eq "" ) { Continue } # not sure how that happens but no need for duplicates
	If ( -Not $name ) { Continue } # not sure how this happens either
	$target = $name + "(" + $ipTarget + ")"
	Write-Output "Removing $target"
	Write-Logs "FAIL" $target "Linux checks" "No privileged ssh access. Unable to perform any Linux checks on $target. Please check manually as needed."
}

#### END LINUX CHECKS ####

##############################################################################
##### BEGIN WINDOWS CHECKS
##############################################################################

#####################################################################################
##### Check Windows machines (valid IP, DHCP and DNS, L1 and L2)
#####################################################################################

# Get Layer 1 Windows VMs
Write-Output "Checking L1 Windows: valid IP, DHCP and DNS..."
$Layer1Windows = @{}
$windowsMachines = @{}
$lines = Get-Content -Path $layerOneInfo
Foreach ($line in $lines) {
	If ( $line -eq "" -Or $line -Like '#*' ) { Continue }
	$IPAddress = ''
	($name,$os,$ipf) = $line.Split(',')
	If ( $os -NotLike '*windows*' ) { Continue }
	$IPAdresses = $ipf.Split()
	$ipAddress = Choose-IP($IPAdresses)
	If ( -Not $ipAddress ) { # if no IPAddress we cannot check further
		Write-Logs "FAIL" $name "L1 IP address" "No IP address for L1 Windows machine. Cannot check."
		Continue # nothing else can be done
	}
	If ( $ipAddress -eq $MCip ) { # Control Center is special
		If ( $WMC ) {
			$dnsName = "controlcenter.$dom"
		} ElseIf ( $LMC ) {
			$dnsName = "mainconsole.$dom"
		}
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
	$wm | Add-Member -MemberType NoteProperty -Name Layer -Value "1"
	
	$Layer1Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
	
}

<#
# handy during dev for debugging
If ( Test-Path "layer1windows.csv" ) { Remove-Item -Path "layer1windows.csv" }
Foreach ( $ipTarget in $Layer1Windows.keys ) {
		$Layer1Windows[$ipTarget] | ConvertTo-CSV | Add-Content "layer1windows.csv"
}
#>

#
# Get Layer 2 Windows VMs
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

$Layer2Windows = @{}
If ( $vcPresent ) { 
	Write-Output "Checking L2 Windows: valid IP, DHCP and DNS..."
	$allvms = Get-VM -ErrorAction SilentlyContinue | where { $_.GuestId -like "*windows*" } # $vm.Guest.OSFullName is blank if powered off so use $vm.GuestId instead.
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
		$wm | Add-Member -MemberType NoteProperty -Name off -Value $false
	}
	
	# does it have an IP address?
	# DEBUG
	#Write-Output "$name vm.Guest.IPAdrress: " $vm.Guest.IPAddress
	
	$nameIP = get-L2-IP $name "Windows"
	If ( -Not $nameIP ) { Continue } # Nothing can be done.
	
	# 08/18/2020 added logic for L2 NAT
	($dnsName,$dnsIP,$vmIP,$IPAddress) = $nameIP.Split(":")
	
	If ( ( $dnsIP -ne "unknown" ) -And ($dnsIP -ne $vmIP) ) { 
		Write-Output "NAT detected for $name. vmIP: $vmIP dnsIP: $dnsIP"
	}
	If ( $dnsIP -ne "unknown" ) {
		$IPAddress = $dnsIP
	} ElseIf ( $vmIP -ne "" ) {
		$IPAddress = $vmIP
	} ElseIf ( $IPAddress -eq "" ) {
		Write-Output "No IP address for $name. Skipping."
		restorePowerState $name $wm.Off
		Continue
	}
	$target = $name + "(${IPAddress})"
	#Write-Host "target: $target"
		
	# should not be in DHCP range
	If ( Check-DHCP $IPAddress ) {
		Write-Logs "WARN" $target "L2 DHCP" "L2 $IPAddress is in DHCP range. Please do NOT use this IP in the lab manual."
	}
	
	# DEBUG
	#Write-Output "Get Layer 2 VM $name IPAddress $IPAddress"
	
	$wm | Add-Member -MemberType NoteProperty -Name Name -Value $name
	$wm | Add-Member -MemberType NoteProperty -Name OS -Value $vm.Guest.OSFullName
	$wm | Add-Member -MemberType NoteProperty -Name dnsName -Value $dnsName
	$wm | Add-Member -MemberType NoteProperty -Name ipAddress -Value $IPAddress
	$wm | Add-Member -MemberType NoteProperty -Name dnsIP -Value $dnsIP
	$wm | Add-Member -MemberType NoteProperty -Name Layer -Value "2"
	$wm | Add-Member -MemberType NoteProperty -Name access -Value $true

	$Layer2Windows[$IPAddress] = $wm
	$windowsMachines[$IPAddress] = $wm
	
	# if we powered it on, power it off before we figure out the next Windows L2 VM
	restorePowerState $name $wm.Off
	
} # End Get Layer2 Windows VMs

<#
# handy during dev for debugging
If ( Test-Path "layer2windows.csv" ) { Remove-Item -Path "layer2windows.csv" }
Foreach ( $ipTarget in $Layer2Windows.keys ) {
		$Layer2Windows[$ipTarget] | ConvertTo-CSV | Add-Content "layer2windows.csv"
}
#>

##############################################################################
#####  BEGIN WINDOWS CHECKS LAYER ONE AND LAYER TWO
#####
#####    Windows firewall, activation, Chrome updates, 
#####	password aging, NTP, time delta, VMXNET3(2012), 
#####	skipRestart (Win7, Win2K3 and Win2k8)
##############################################################################

# initialize the removeWindowsMachines array
$removeWindowsMachines = @()

# BEGIN Windows checks loop (Layer 1 and Layer 2)
Write-Output "Checking Windows firewall, activation, Chrome updates, password aging, NTP, time delta, VMXNET3(2012), skipRestart (Win7, Win2K3 and Win2k8) ..."

Foreach ($ipTarget in $windowsMachines.keys) {  # this is the windows check loop. power on, do all checks, power off
	$errorVar = $null
	$name = $windowsMachines[$ipTarget].Name
	$hostName = $windowsMachines[$ipTarget].dnsName
	#Write-Host "name: $name hostName: $hostName"
	If ( $hostname -eq "" ) { $hostName = $name } # if not in DNS use the Name instead
	$target = $name + "(${IPAddress})"
	#Write-Host "target: $target"
	$os = $windowsMachines[$ipTarget].OS
	If ( $windowsMachines[$ipTarget].Layer -eq "2" ) { $vm = Get-VM -Name $name }
	
	#DEBUG
	#Write-Output "DEBUG ipTarget $ipTarget  hostName $hostName"
	If ( $ipTarget -eq "" ) {
		Write-Output "Empty ipTarget for $hostName. Adding to removeWindowsMachines"
		$removeWindowsMachines += $ipTarget
		Continue
	}
	
	# Power on L2 Windows machine for checks then power off when complete
	If ( $windowsMachines[$ipTarget].Off ) { # has to be Layer 2
		Write-Output "Powering on L2 Windows VM $hostName to perform Windows checks..."
		$result = start-L2 $name
		If ( $snap -ne $null ) {
			$snap = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
		}
		$fwCtr = 0
		While ( $true ) {
			If ( $fwCtr -ge 5 ) {  # opportunity to use Invoke-VMScript
				$windowsMachines[$ipTarget].access = $false
				Write-Logs "FAIL" $target "L2 Windows Access" "No ping response on L2 $target after power on. Please check firewall manually."
				Write-Output "Powering off L2 machine $hostName since no access after power on..."
				$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false
				$removeWindowsMachines += $ipTarget
				Break
			}
			
			#DEBUG
			#Write-Host "ipTarget $ipTarget"
			If ( !$ipTarget ) {
				($junk,$ipTarget) = $target.Split('(')
				$ipTarget = $ipTarget.Trim(')')
				Write-Output "PowerShell has lost it's mind on $target. The ipTarget variable is NULL and it should NOT be."
				Write-Output "Skipping tests for $target..."
				Write-Logs "INFO" $target "PowerShell weirdness" "ipTarget variable is NULL."
				Break
			}
			If ( $psVersion -ge 6 ) { # current PowerShell support
				If ( Test-Connection -TargetName $ipTarget -Quiet ) { Break	}
			} Else { # old versions (why using?)
				If ( Test-Connection -ComputerName $ipTarget -Quiet ) { Break	} 
			}
			
			Start-Sleep $sleepSeconds
			$fwCtr++
		} 
	}
	If ( $windowsMachines[$ipTarget].access -eq $false ) { # only false at this point if L2 power on didn't help so just skip it. (no ping)
		Continue
	} 
	
	# Report Card #23 All Windows OS firewalls disabled
	Write-Output "checkWindowsFirewall.ps1 $hostName $ipTarget"
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsFirewall.ps1 `"$hostName`" $ipTarget"
	#Start-Sleep $sleepSeconds
	# check output.txt and add to remove Windows machines arrary
	If ( Test-Path "/tmp/output.tst" ) {
		$output1 = Get-Content -Path "/tmp/output.txt"
		Foreach ( $line in $output ) {
			If ( $line -like '*cannot check*' ) { # cannot reach this machine (firewall on?)
				$windowsMachines[$ipTarget].access = $false
				If ( $windowsMachines[$ipTarget].off ) { 
					$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false
				}
				$removeWindowsMachines += $ipTarget
				Break
			}
		}
	}
	If ( $windowsMachines[$ipTarget].access -eq $false ) { Continue } # probably firewall issue. nothing we can do to check unless Invoke-VMScript (can ping but cannot get in to check firewall)
	
	# Report Card #29 Windows OS license ID changed from default
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget nolog" # first run always fails for some reason
	Start-Sleep $sleepSeconds
	
	#43 Check for updates: Never (Windows task Google check for updates disabled)
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget nolog" # first run always fails for some reason
	Start-Sleep $sleepSeconds

	# Report Card #65 Include skipRestart utility if Win7/2K3/2k8
	If ( ($os -like "*2008*") -or ($os -like "*2003*") -or ($os -like "*Windows*7*") ) {
		Write-Host checkSkipRestart.ps1
		Invoke-Expression "pwsh -File $PSScriptRoot/checkSkipRestart.ps1 `"$hostName`" $ipTarget"
	} Else {
		Write-Logs "PASS" $target "skipRestart Win7/2K3/2k8" "$hostName with OS $os does not need skipRestart."
	}
	Start-Sleep $sleepSeconds

	# Report Card #46 passwords set to NEVER expire
	If ( $ipTarget -eq "$MCip" -And $WMC ) {
		Write-Host "pwsh -File $PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget VCF"
		Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget VCF" # DC is special case
	} Else {
		Write-Host "$PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsPasswords.ps1 `"$hostName`" $ipTarget"
	}
	Start-Sleep $sleepSeconds

	# Report Card #52 VMs syncd to ntp.corp.vmbeans.com or Main Console
	If ( $ipTarget -ne "$MCip" -And $ntpdOK ) { # Checking the Main Console makes no sense
		Write-Host "$PSScriptRoot/checkWindowsTime.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsTime.ps1 `"$hostName`" $ipTarget"
		Start-Sleep $sleepSeconds
	}

	# Report Card #32 Use VMXNET3 adpater on all Windows 2012 VMs
	If ($windowsMachines[$ipTarget].OS -like '*2012*') {
		Write-Host "$PSScriptRoot/checkWindows2012vmxnet3.ps1 `"$hostName`" $ipTarget"
		Invoke-Expression "pwsh -File $PSScriptRoot/checkWindows2012vmxnet3.ps1 `"$hostName`" $ipTarget"
		Start-Sleep $sleepSeconds
	}

	#62 Desktop shortcut names not truncated
	Write-Host "$PSScriptRoot/checkWindowsShortCuts.ps1 `"$hostName`" $ipTarget"
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsShortCuts.ps1 `"$hostName`" $ipTarget"
	Start-Sleep $sleepSeconds 

	# Report Card #29 Windows OS license ID changed from default
	Write-Host "$PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget log"
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsActivation.ps1 `"$hostName`" $ipTarget log" # hopefully this second run works
	Start-Sleep $sleepSeconds
	
	#43 Check for updates: Never (Windows task Google check for updates disabled)
	Write-Host "$PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget log"
	Invoke-Expression "pwsh -File $PSScriptRoot/checkWindowsChromeUpdates.ps1 `"$hostName`" $ipTarget log" # hopefully this second run works
	Start-Sleep $sleepSeconds
	
	# if we powered on the machine, double check that it is powered off
	If ($WindowsMachines[$ipTarget].Off) {
		Write-Output "End of Windows checks for $hostName. Powering off $hostName..."
		restorePowerState $name $wm.Off
	}

} # END Windows check loop

# remove the bad and unreachable Windows machines - no further testing
Foreach ($ipTarget in $removeWindowsMachines) {
	$hostName = $windowsMachines[$ipTarget].Name
	$target = $hostName + "(" + $ipTarget + ")"
	Write-Output "Removing $target"
	Write-Logs "FAIL" $target "Windows checks" "Unable to check $target. Please check manually as needed."
	$windowsMachines.Remove($ipTarget)
	If ( $Layer1Windows[$ipTarget] ) { $Layer1Windows.Remove($ipTarget) }
	If ( $Layer2Windows[$ipTarget] ) { $Layer2Windows.Remove($ipTarget) }
}

##############################################################################
##### END WINDOWS CHECKS
##############################################################################

#64 Main Console screen resolution = 1024 x 768
# 2/5/2020 increasing default screen resolution to 1280 x 800
# Moved to checkcoreteamtools.ps1

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
	If ( $Layer1Linux[$ipTarget].Name -Like "*esx*" ) { Continue } # will get vESXi utilization from vCenter (no top)
	If ( $ipTarget -eq $stgIP ) { Continue } # FreeNAS BSD top is different
	If ( $ipTarget -eq $rtrIP ) { Continue } # router is most likely not an issue can investigate later
	If ( $ipTarget -eq "192.168.0.2" ) { Continue } # other router IP
	If ( $ipTarget -eq "10.1.1.1" ) { Continue } # another router IP
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
	If ( $vm.ProvisionedSpaceGB -ne 0 ) {
		$item.Storage = "{0:N2}%" -f ( ($vm.UsedSpaceGB / $vm.ProvisionedSpaceGB) * 100)
	} Else {
		$item.Storage = "N/A"
	}
	$report += $item
}
$output = $report | Sort-Object -Property Name | Format-Table -AutoSize
Out-File -FilePath $invUtilReport -Append -InputObject $output -Encoding ASCII
Write-Output "-----------" | Add-Content $invUtilReport
$quiet = New-Item -Force -Path "$logDir" -Name "HTML" -ItemType "directory"
# copy to simple name for AutoCheck HTML report
Copy-Item -Force $invUtilReport "$logDir/HTML/invutilrpt.txt"

# After vCenter has stabilized, check for vSphere alarms before disconnecting
# get triggered alarms on all datacenters
If ( $vcPresent ) { 
	Write-Output "Checking vCenter alarms..."
	$folders = Get-Folder -Name "Datacenters"
} ElseIf ($vcsToTest.Length -ge 1) {
	Write-Logs "FAIL" $vcsToTest "vCenter connections" "No vCenters available even though listed in vCenters.txt"
	$vcsToTest = @()
} 

Foreach ($folder in $folders) { 
	Foreach ($triggered in $folder.ExtensionData.TriggeredAlarmState) {
		$object = Get-View -Id $triggered.Entity
		$name = $object.Name
		$alarmDef = Get-View -Id $triggered.Alarm
		$alarmName = $alarmDef.Info.Name
		$severity = $triggered.OverallStatus
		Write-Logs "INFO" $name "triggered alarm" "$name $severity alarm: $alarmName"
	}
}

#Write-Output "$(Get-Date) disconnecting from $vcserver ..."
If ( $vcPresent ) {
	Disconnect-VIServer -Server * -Force -Confirm:$false
}

# final clean up

If ( $WMC ) {
	If ( Test-Path "$mcholroot/run.ps1" ) { Remove-Item -Force "$mcholroot/run.ps1" }
}

endAutoCheck
