# checkcoreteamtools.ps1 12-May 2025

# supported on Manager only
# captains cannot change hol files in /home/holuser/hol

# need this stuff at a minimum

$autocheckModulePath = Join-Path $PSSCriptRoot -ChildPath "autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Output "FATAL: Cannot find autocheckfunctions.psm1. Abort."
	Exit
}

<#
# Overwrite logs - useful in development but do not use for production
Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file
Set-Content -Path $csvDetailFile -Value "" -NoNewline # overwrite existing log file
#>

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

Write-Output ("Checking Core Team files on the Manager and the Main Console...")

$labStartup = "/home/holuser/hol/labstartup.py"
$labStartupDate = "15 April 2025 12:00 AM"
$labStartupFunctions = "/home/holuser/hol/lsfunctions.py"
$labStartupFunctionsDate = "07 April 2025 12:00 AM"

#64 Main Console screen resolution = 1024 x 768
Write-Output "Checking screen resolution..."
# 2/5/2020 increasing default screen resolution to 1440 x 900
$defaultScreenWidth = 1440
$defaultScreenHeight= 900

$pass = $true
If ( $WMC ) {
	# PS script runs remotely
	'Get-CimInstance CIM_VideoController | Select CurrentHorizontalResolution, CurrentVerticalResolution' | Set-Content -Path  "$mcholroot/run.ps1"
	$output = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	If ( $output -Like "*${defaultScreenWidth}*" ) { $width = $defaultScreenWidth}
	If ( $output -Like "*${defaultScreenHeight}*" ) { $height = $defaultScreenHeight }
	Remove-Item "$mcholroot/run.ps1"
} ElseIf ( $LMC ) {
        Copy-Item "$PSScriptRoot/getres.sh" -Destination "/lmchol/tmp/getres.sh"
	$cmd = "/bin/bash /tmp/getres.sh"
        $resolution = remoteLinuxCmdLMC console holuser $linuxpassword $cmd "-X"
	($width, $heightraw)  = $resolution.Split("x")
        $height = $heightraw.Trim()
}
If ( $width -ne $defaultScreenWidth -Or $height -ne $defaultScreenHeight) {  
		$pass = $false
		$screenSize = "{Width=$width x Height=$height}"
}

If ( $pass ) {
	Write-Logs "PASS" "Main Console" "Screen Resolution" "Main Console has correct $defaultScreenWidth x $defaultScreenHeight screen resolution."
} Else {
	Write-Logs "FAIL" "Main Console" "Screen Resolution" "Main Console has non-standard screen resolution of $screenSize"
}

# 2024: check remotely on a WMC or LMC
If ( $WMC ) {
	$mc = "/wmchol"
	$tools = "$mc/HOL/Tools"
	$startup = "$mc/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"
	# verify the files exist 
	$theFiles = ("$tools/baretail.exe",
	"$tools/Configure-ESXi-Hosts.ps1",
	"$tools/fwoff.bat",
	"$tools/fwon.bat",
	"$tools/HOL-Licenses.psm1",
	"$tools/HOL-SCSI.psm1",
	"$tools/NewIsoFileFunctions.ps1",
	"$tools/PLINK.EXE",
	"$tools/proxyoff.bat",,
	"$tools/proxyon.bat",
	"$tools/PSCP.EXE",
	"$tools/PsExec64.exe",
	"$tools/sdelete.exe",
	"$tools/Remove-HolEsxiBase.ps1",
	"$tools/vPodChecker.ps1"
	)
} ElseIf ( $LMC ) {
	$mc = "/lmchol"
	$tools = "$mc/hol/Tools"
	$startup = "$mc/home/holuser/.config/autostart"
	# verify the files exist 
	$theFiles = ("$mc/home/holuser/.conky/conky-startup.sh",
	"$tools/config_test.yaml",
	"$tools/Configure-ESXi-Hosts.py",
	"$tools/HOL-SCSI.psm1",
	"$tools/hol-ssl.py"
	)	
}

# confirm that $labStartup has a matching labSku to $vPodName.
$labSKUline = "vPod_SKU = " + $vPodName.SubString(0,8)

If ( (Select-String -Path $configIni -Pattern $labSKUline) -ne "" ) {
	Write-Logs "PASS" "Core Team" "Lab Files" "$labStartup set the vpod_sku correctly. Thanks!"
} Else {
	Write-Logs "FAIL" "Core Team" "Lab Files" "$labStartup is not setting vpod_sku correctly. Should be $labSKUline"
}

$mgrcrons = Invoke-Expression "crontab -l"
If ( $mgrcrons -Match "labstartup" ) { 
	Write-Logs "PASS" "Core Team" "Lab Files" "Cron entry for labstartup.sh on the Manager is present."
} Else {
	Write-Logs "WARN" "Core Team" "Lab Files" "Cron entry for labstartup.sh missing on the Manager."
}

If ( $LMC -eq $true ) {
	$crons = remoteLinuxCmdLMC console holuser $linuxpassword "crontab -l"
	If ( $crons -Like "*conkywatch*" ) {
		Write-Logs "PASS" "Core Team" "Lab Files" "Cron entry for conky on the LMC is present."
	} Else {
		Write-Logs "WARN" "Core Team" "Lab Files" "Cron entry for conky on the LMC is NOT present."
	}
}

$fileStatus = "PASS"

ForEach ( $file in $theFiles ) {
	#Write-Output $file
	If ( $WMC ) { 
		$dispFile = $file.Replace('/', '\')
		$dispFile = $dispFile.Replace('\wmchol', 'C:')
	} ElseIf ( $LMC ) { 
		$dispFile = $file.Replace('/wmchol', '')
	}
	If ( Test-Path $file -PathType leaf -IsValid ) {
		$list = $list + "`n$dispfile"
	} Else {
		$fileStatus = "FAIL"
		Write-Logs "FAIL" "Core Team" "Lab Files" "Missing Core Team critical lab file: $dispFile"
	}
}

If ( $fileStatus -eq "PASS" ) {
	Write-Logs "PASS" "Core Team" "Lab Files" "Found all Core Team critical lab files: $list"
}

# now check the versions - want equal date or later

checkCTVersion $labStartup $labStartupDate
checkCTVersion  $labStartupFunctions $labStartupFunctionsDate

Write-Output "Checking $LabStartupFunctions for edits..."
# as of RTM1 May 12, 2025
$refLabStartupFunctionsHash = "9c0111028b3bc942a78650a28014cf249d28d008381e98c972ca8d66e0e0d571"
$HashAlgorithm = 'SHA256' #one of the supported types: MD5, SHA1, SHA256, SHA384, SHA512
$lsfHash = Get-FileHash -Path $labStartupFunctions -Algorithm $HashAlgorithm
$lsFunctionsHash = $lsfHash.Hash.ToLower()
If ( $refLabStartupFunctionsHash -Match $lsFunctionsHash ) {
	Write-Logs "PASS" "Core Team" "$LabStartupFunctions" "No edits detected to $LabStartupFunctions"
} Else {
	Write-Output "lsFunctionsHash: $lsFunctionsHash"
	Write-Logs "FAIL" "Core Team" "$LabStartupFunctions" "$LabStartupFunctions has been changed."
}

# 01-March 2024 vPodRouterHOL checks
$errorVar = ''
$getrulesDate = "05 April 2025 00:00 AM"
Write-Output "Checking Router..."
# verify getrules.sh
$getRules = "/root/getrules.sh"
$localRules = "/tmp/getrules.sh"
Write-Output "Copying $getRules on the router to $localRules locally..."
# copy the file locally and just run the command.
$out = scpLMC "root@router:$getRules" $localRules  $rtrpassword
checkCTVersion  $localRules $getRulesDate

# get checksum on getrules.sh
$getrulesChecksumRef = "2192429393"  
$grCKsumCmd = "/usr/bin/cksum /tmp/getrules.sh | cut -f1 -d' ' > /tmp/rulescksum"
Invoke-Expression  $grCKsumCmd
$grkCKsum = Get-Content -Path "/tmp/rulescksum"

Try {
	If ( $getrulesChecksumRef -Match $grCKsum ) {
		Write-Logs "PASS" "Core Team" "getrules.sh" "No edits detected to $getRules on vPodRouterHOL"
	} Else {
		Write-Output "$getRules checksum: $grCKsum"
		Write-Logs "FAIL" "Core Team" "getrules.sh" "$getRules on vPodRouterHOL has been changed."
	} 
} Catch {
	Write-Logs "FAIL" "Core Team" "getrules.sh" "Cannot checksum $getRules on vPodRouterHOL."
}

# get /root/version.txt if it exists
Write-Output "Checking /root/version.txt on router..."
Try {
	$out = scpLMC "root@router:/root/version.txt" "/tmp/version.txt"  $rtrpassword
	$rtrVer = Get-Content -Path "/tmp/version.txt"
	Write-Logs "INFO" "Core Team" "router Version" $rtrVer
} Catch {
	Write-Logs "FAIL" "Core Team" "router Version" "Cannot check router version. $errorVar"
}

# check the time zone - UTC is PASS, not UTC FAIL
$tzCmd = 'date +%Z'
$rtrTZ = remoteLinuxCmdLMC "router" $linuxuser $rtrpassword $tzCmd

If ( $rtrTZ -Like "*UTC*" ) {
	Write-Logs "PASS" "Core Team" "router Time Zone" "router is set to UTC time zone."
} ElseIf ( $errorVal.length -gt 0 ) {
	Write-Logs "FAIL" "Core Team" "router Time Zone" "Cannot check time zone on router $errorVar"
} Else {
	Write-Logs "FAIL" "Core Team" "router Time Zone" "router must use UTC time zone and not $rtrTZ."
}

# check for authorized_keys file on the router
Write-Output "Checking for ssh auth (passwordless login) from on router"
$output = remoteLinuxCmdLMC "router" $linuxuser $rtrpassword "ls .ssh"
If ( $output -Like "*authorized_keys*" ) {
	# check for ssh auth to router
	If ( $WMC ) {
		# run the command without a password to test aah auth
		$winCmd = "\hol\Tools\plink.exe -batch root@router date"
		$output = RunWinCmd $winCmd ([REF]$result) 'mainconsole' 'Administrator' $password
	} Else{
		$output = remoteLinuxCmdLMC mainconsole holuser $linuxpassword "ssh root@router date"
	}
	If ( $output -Like "*UTC*" ) {
		Write-Logs "FAIL" "Core Team" "Router Security" "SSH AUTH must NOT be enabled on the router."
	} Else {
		Write-Logs "PASS" "Core Team" "Router Security" "No SSH AUTH detected on router."
	}
}

If ( $WMC ) {
	$tziPath = 'HKLM:SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
	"Get-ItemPropertyValue -Path $tziPath -Name `"RealTimeIsUniversal`"" | Set-Content -Path "$mcholroot/run.ps1"
	$tziConfig = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	If ( $tziConfig -Like "*1" ) {
		Write-Logs "PASS" "Main Console" "Critical Time Zone Fix" "Thank you. Time will work as expected in your lab."
	} Else {
		Write-Logs "FAIL" "Main Console" "Critical Time Zone Fix" "Critical update needed on Main Console. Please fix time zone information in Windows Registry."
		Write-Output "Critical update needed on Main Console. Please fix time zone information in Windows Registry."
	}
	Remove-Item "$mcholroot/run.ps1"
}

# check DNS forwarders
Write-Output "Checking DNS Forwarders..."
If ( $WMC ) {
	$fwd = ''
	"`$fwd = ''
	`$fwdObj = Get-DnsServerForwarder
	Foreach ( `$ip in `$fwdObj.IPAddress) {
		If ( `$fwd -ne '' ) { `$fwd += ':' }
		`$fwd += `$ip
	}
	Write-Host `$fwd	" | Set-Content -Path "$mcholroot/run.ps1"
	$out = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	$out = $out.Replace(' ', ':')
	$parts = $out.Split(':')
	ForEach ( $ip in $parts ) {
		If ( $ip -Like "*run*" ) { Continue }
		If ( $fwd -ne '' ) { $fwd += ':' }
		$fwd += $ip
	}
	Remove-Item "$mcholroot/run.ps1"
} ElseIf ( $LMC ) {
	Write-Output "Checking DNS forwarders on LMC..."
	# nmcli device show ens33 | grep IP4 ( will show DNS servers from GUI)
	$lcmd = "nmcli device show ens33 | grep IP4.DNS"
	$nmscliOut = remoteLinuxCmdLMC console holuser $linuxpassword $lcmd
	ForEach ( $line in $nmscliOut ) {
		$tmp = $line.Split()		
		$ip = $tmp[$tmp.Length-1]
		If ( $ip -ne "192.168.110.10" ) {
			If ( $fwd -ne '' ) { $fwd += ":" }
			$fwd += $ip
		}
	}
	# check entries in /etc/resolv.conf - NetworkManager overwrites anyway)
	scpLMC "holuser@console:/etc/resolv.conf" "/tmp/resolv.conf" $password
	$resolv = Get-Content -Path "/tmp/resolv.conf"
	ForEach ( $line in $resolv ) {
		($junk, $ip) = $line.Split()
		If ( $line -Like "*nameserver*" -And $ip -ne "127.0.0.53" ) {
			If ( $fwd -ne '' ) { $fwd += ":" }
			$fwd += $ip
		}
	}
}

# clean up the string
$fwd = $fwd.Replace("'", "")
$fwd = $fwd.Replace("\r", "")
$fwd = $fwd.Replace("[", "")
$fwd = $fwd.Replace("]", "")
$fwd = $fwd.TrimEnd(":")
#$fwd = $fwd.SubString(0,$fwd.Length -1 )

$foundFwd = $false
ForEach ($pattern in $dnsForwarders){
	#Write-Host "pattern: $pattern source: $source"
	If ( $fwd -Like "*$pattern*" ) {
		$foundFwd = $true
		Write-Logs "PASS" "Core Team" "DNS Forwarders" "DNS forwarders include HOL standards. Forwarders ($fwd)"
		Break
	}
}
If ( ! $foundFwd ) {
	Write-Logs "FAIL" "Core Team" "DNS Forwarders" "DNS forwarders are non-standard ($fwd). Please change to 8.8.8.8 and 8.8.4.4."
}

#56 Desktop Background
Write-Output "Checking desktop background image..."
$newWPsize = 103436
$defaultWPsize = $newWPsize

If ( $WMC ) {
	$defaultWPPath =  Join-Path -Path $mcholroot -ChildPath "TranscodedWallpaper.jpg"
	"Get-ItemPropertyValue -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper" | Set-Content -Path "$mcholroot/run.ps1"
	$out = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	$parts = $out.Split(' ')
	ForEach ( $p in $parts ) {
		If ( $p -Like "*run*" ) { Continue }
		$currentWallpaperPath += $p
	}
	$currentWallpaperPath = "$mc" + $currentWallpaperPath.Substring(1)
	$currentWallpaperPath = $currentWallpaperPath.Replace('\', '/')
	$currentWallpaperPath = $currentWallpaperPath.Replace('//', '/')
	$currentWallpaperPath = $currentWallpaperPath.Replace("'C", "")
	$currentWallpaperPath = $currentWallpaperPath.Replace("/r','']", "")
	Write-Host "currentWallpaperPath $currentWallpaperPath"
	Write-Host "defaultWPPath $defaultWPPath"
	$currentWallpaper = Get-Item -Path $currentWallpaperPath
	Remove-Item "$mcholroot/run.ps1"
} ElseIf ( $LMC ) {
	$defaultWPPath =  "/lmchol/home/holuser/.local/share/backgrounds/2025-01-09-13-28-16-TranscodedWallpaper.jpg"
	$lcmd = "gsettings get org.gnome.desktop.background picture-uri"
	$output = remoteLinuxCmdLMC console holuser $linuxpassword $lcmd
	$tmpOut = $output.Split()
	$currentWallpaperPath = $tmpOut[0]
	#Write-Host ".${currentWallpaperPath}."
	$currentWallpaperPath = $currentWallpaperPath -Replace "`'", ""
	$currentWallpaperPath = $currentWallpaperPath -Replace "file://", "/lmchol"
	$currentWallpaper = Get-Item -Path $currentWallpaperPath
}

# check the size
If ( $currentWallpaper.Length -eq $defaultWPsize ) { # 1/26/2021 new wallpaper
	$wpSize = $true
} ElseIf ( $currentWallpaper.Length -eq $oldWPsize ) {
	$wpSize = $false
	Write-Logs "WARN" "Main Console" "Wallpaper" "Wallpaper on Main Console is using old image. Please update to the new image if your lab manual allows."
}Else {
	$wpSize = $false
	Write-Logs "FAIL" "Main Console" "Wallpaper" "Wallpaper on Main Console has a non-standard file size."
}

# do we care about the file path?
If ( $wpSize ) {
	Write-Logs "PASS" "Main Console" "Wallpaper" "Wallpaper on Main Console has the correct size."
}

# check for the dWatcher.ps1 and dWatcher.bat script for desktopInfo64
If ( $WMC ) {	
	If ( Get-ChildItem "$mc/DesktopInfo/dWatcher.ps1" ) {
		Write-Logs "PASS" "Core Team" "DesktopInfo" "The dWatcher.ps1 is present."
	} Else {		
		Write-Logs "FAIL" "Core Team" "DesktopInfo" "The dWatcher.ps1 is NOT present."
	}		
	If ( Get-ChildItem "$mc/DesktopInfo/dWatcher.bat" ) {
		Write-Logs "PASS" "Core Team" "DesktopInfo" "The dWatcher.bat is present."
	} Else {		
		Write-Logs "FAIL" "Core Team" "DesktopInfo" "The dWatcher.bat is NOT present."
	}			
	$dWatcherLink = "$mc" + '/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/dWatcher*.lnk'
	If ( Test-Path $dWatcherLink ) {
		Write-Logs "PASS" "Core Team" "DesktopInfo" "The DesktopInfo watcher is configured to run on Startup."
	} Else {
		$message1 = "The DesktopInfo watcher is NOT configured to run on Startup."
		$message2 = "Please create a shortcut to C:\DesktopInfo\dWatcher.bat in"
		$message3 = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs/StartUp"
		Write-Logs "FAIL" "Core Team" "DesktopInfo" "$message1 $message2 $message3"
	}
}

#4 vPod was created from approved templates - copy version.txt to $logDir
$vPodVersion = "$mc/hol/version.txt"
If ( Test-Path $vPodVersion ) {
	Copy-Item -Force $vPodVersion $logDir
} Else {
	Write-Logs "FAIL" "VERSION File" $vPodVersion "Failed to find version.txt in $labStartupRoot"
}

Write-Output "Retrieving proxy log and firewall rules from the router... "
#24 vPodRouter iptables firewall working as expected - Doug to make accessible to holuser
#25 vPodRouter Proxy working as expected - Doug to make accessible to holuser (check Windows Internet proxy setting)

# 06/08/2020 add /etc/squid/* and /root/iptablescfg.sh to $routerSource
$proxyFileCopy = @"
"cp /etc/squid/* /home/holuser/running_config"
"@
$fwFileCopy = @"
"cp /root/iptablescfg.sh /home/holuser/running_config"
"@

$quiet = remoteLinuxCmdLMC "router" $linuxuser $rtrpassword $proxyFileCopy

$quiet = remoteLinuxCmdLMC "router" $linuxuser $rtrpassword $fwFileCopy

$routerSource = "router:/home/holuser/running_config/*"
$localDest = Join-Path -Path $logDir -ChildPath "router"
If ( Test-Path $localDest) {
	Remove-Item -Path $localDest -Recurse -Force 
} 
New-Item -Path $localDest -ItemType Directory -ErrorAction 0 | Out-Null
$msg = scpLMC "root@$routerSource" $localDest $rtrpassword
Invoke-Expression "chmod a+w $localDest/*"

If( $msg -match "no such file or directory" ) {
	Write-Output "No files found."
	Write-Logs "FAIL" "Router" "Proxy/Firewall settings" "No files found at $routerSource."
} Else {
	Remove-Item -Path "$localDest/*.orig"
	Write-Output "Copied $routerSource to $localDest."
	Write-Logs "INFO" "Router" "Proxy/Firewall settings" "Copied $routerSource to $localDest."
}

Write-Output "Collecting core lab files..."
#19 No labStartup.log errors - copy LabStartup.log to $logDir
$labStartupLog = "$labStartupRoot/labstartup.log"
Copy-Item -Force $labStartupLog $logDir

#20 Custom labstartup script(s) working as expected - copy LabStartup.ps1 to $logDir
If ( Test-Path "$logDir/$lab_sku" ) { Remove-Item -Recurse -Force "$logDir/$lab_sku" }
$quiet = New-Item -ItemType "directory" -Path "$logDir/$lab_sku"
$files = Get-ChildItem -Path $resourceFileDir -Recurse
ForEach ( $file in $files ) {
	Copy-Item -ErrorAction SilentlyContinue -Force $file "$logDir/$lab_sku"
}

# legacy check - since we're doing a manual run, chances are the shutdown tracker has already been dismissed.
<#
# If ( $WMC ) {
# not listed in report card but Main Console needs to be shut down correctly
$windowTitle = "Shutdown Event Tracker"
Write-Output "Checking for Shutdown Event Tracker..."
# load VisualBasic - borrowing code from SkipRestart.ps1
If ( $psVersion -eq 5 ) {
	[void] [System.Reflection.Assembly]::LoadWithPartialName("'Microsoft.VisualBasic")
} Else {
	Add-Type -Path 'C:\Program Files\PowerShell\7\ref\Microsoft.VisualBasic.dll'
}

Try {
	[Microsoft.VisualBasic.Interaction]::AppActivate($windowTitle)
	Write-Logs "FAIL" "Main Console" $windowTitle "Found $windowTitle window! Main Console not shut down properly."
}
Catch {	
	Write-Logs "PASS" "Main Console" $windowTitle "$windowTitle Window was not found. Thanks for shutting down properly."
}
}
#>
