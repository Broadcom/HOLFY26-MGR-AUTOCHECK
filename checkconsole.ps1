# 05-May 2024

# need this stuff at a minimum

$autocheckModulePath = Join-Path $PSSCriptRoot -ChildPath "autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Output "FATAL: Cannot find autocheckfunctions.psm1. Abort."
	Exit
}

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

#57 Recycle Bin empty
Write-Output "Checking Recycle Bin..."
If ( $WMC ) {
	"`$recycleBin = (New-Object -ComObject Shell.Application).Namespace(0xa)" | Set-Content -Path "$mcholroot/run.ps1"
	"If ( (`$recycleBin.Items()).Count -gt 0 ) { Write-Output 'FAIL' " | Add-Content -Path  "$mcholroot/run.ps1"
	"} Else { Write-Output 'PASS' } " | Add-Content -Path  "$mcholroot/run.ps1"
	$recycleBin = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	Remove-Item "$mcholroot/run.ps1"
} ElseIf ( $LMC ) {
	$recycleBin = "$mc/home/holuser/.local/share/Trash/files"
	If ( -Not (Test-Path $recycleBin) ) { $recycleBin = "PASS"
	} ElseIf ( (Get-ChildItem -Path $recycleBin).Length -gt 0 ) { $recycleBin = "FAIL"
	} Else { $recycleBin = "PASS" }
}
If ( $recycleBin -eq "FAIL" ) {
	Write-Logs "FAIL" "Main Console" "Recycle Bin" "Recycle Bin on Main Console is NOT empty."
} Else {
	Write-Logs "PASS" "Main Console" "Recycle Bin" "Recycle Bin on Main Console looks good."
}


#59 Removed temporary storage / scratch disk
Write-Output "Checking temporary storage / scratch disk..."
If ( $WMC ) {
	Copy-Item "/home/holuser/autocheck/checkwmcscratch.ps1" "$mcholroot/run.ps1"
	$scratchTmp = RunWinCmd "pwsh -File C:\hol\run.ps1" ([REF]$result) 'mainconsole' 'Administrator' $password
	$scratchTmp = $scratchTmp.Replace('\hol\run.ps1', '')
	$scratchTmp = $scratchTmp.Replace('\r', '')
	$scratchTmp = $scratchTmp.Replace("'", "")
	$scratchTmp = $scratchTmp.Replace('.', '')
	$scratchTmp = $scratchTmp.Replace('[', '')
	$scratchTmp = $scratchTmp.Replace(']', '')
	$scratchTmp = $scratchTmp.Replace(',', '')
	$scratchTmp = $scratchTmp.Trim()
	$scratchFields = $scratchTmp.Split('~')
	Write-Logs $scratchFields[1] $scratchFields[2] $scratchFields[3] $scratchFields[4]
	Remove-Item "$mcholroot/run.ps1"
} ElseIf ( $LMC ) {
	Copy-Item "/home/holuser/autocheck/checklmcscratch.ps1" "$mcholroot/run.ps1"
	$scratchTmp = remoteLinuxCmdLMC "mainconsole.$dom" $linuxuser $linuxpassword "pwsh -File /hol/run.ps1"
	#Write-Host $scratchTmp
	$scratchFields = $scratchTmp.Split('~')
	Write-Logs $scratchFields[0] $scratchFields[1] $scratchFields[2] $scratchFields[3]
	Remove-Item "$mcholroot/run.ps1"
}

#58 Temp directory contains no large files (total size <10 MB)
$sizeThreshhold = 10
#60 Remove stray files: installers, downloads
Write-Output "Checking for stray files: installers, downloads, etc..."
If ( $WMC ) {
	$folders = ("$mc/Users/Administrator/Downloads","$mc/Users/Administrator/Documents","$mc/Temp","$mc/Users/Administrator/Desktop")
} ElseIf ( $LMC ) {
	$folders = ($mcholroot, "$mc/home/holuser/Downloads","$mc/home/holuser/Documents", "$mc/home/holuser/Desktop")
}
Foreach ($folder in $folders) {
	#Write-Host $folder
	$dir = $null
	$items = Get-ChildItem -Path $folder -Recurse -ErrorAction SilentlyContinue
	Foreach ($item in $items) {
		#Write-Host $item.Name
		$mode = [String]$item.Mode
		$name = $item.Name
		$lengthMB = [math]::Round($item.Length / 1MB)
		$sizeMB = "$lengthMB MB"
		#$sizeMB = "{0:N2} MB" -f $lengthMB
		#$sizeMB = "{0:N2} MB" -f ((Get-ChildItem $p -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
		#$sizeMB = "{0:N2} MB" -f ((Get-ChildItem $p | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
		$dir += $mode + "`t" + $name + "`t" + $sizeMB + "`n"		
		If ( $item.Name -like '*.rdp' ) {
			$rdpFile = $folder + "\" + $name
			Copy-Item -Force $rdpFile $logDir 
		}
		If ( $folder -Like "*Temp*" ) {
			#$sizeMB = "{0:N2} MB" -f ((Get-ChildItem $p -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
			If ( $lengthMB -gt $sizeThreshhold ) {
				If ( $WMC ) {
					$folderTmp = $folder.Replace($mc, "C:")
					$folderTMP = $folder.Replace('/', '\')
					$slash = "\"
				} ElseIf ( $LMC ) {
					$folderTmp = $folder.Replace($mc, "")
					$slash = "/"
				}	
				Write-Logs "FAIL" "Cleanup" "Large Temp Files" "File $folderTmp$slash$name has size: $sizeMB"
			}
		}
	}
	If ( $WMC ) {
		$folder = $folder.Replace($mc, "C:")
		$folder = $folder.Replace('/', '\')
		$slash = "\"
	} ElseIf ( $LMC ) {
		$folder = $folder.Replace($mc, "")
		$slash = "/"
	}
	$info = "Contents of folder " + $folder + ":`n" + $dir
	Write-Logs "INFO" "Cleanup" "Stray Files" $info
}

Write-Output "Checking README.txt updates..."
#61 README.TXT is complete, no spelling mistakes - check README.txt changed and copy to $logDir
$originalPattern = "big long command line that nobody wants to type"
$defaultReadme = Join-Path -Path $PSScriptRoot -ChildPath "readme.txt"
If ( $WMC ) {
	$labReadme = "$mc/Users/Administrator/Desktop/README.txt"
} ElseIf ( $LMC ) {
	$labReadme = "$mc/home/holuser/Desktop/README.txt"
}
If ( Test-Path -Path $labReadme ) {
	$readme = Get-Content $labReadme
	If ( $readme.Contains($originalPattern) ) {
		Write-Logs "FAIL" "README.txt" "README updates" "README.txt on desktop needs updating."
	} Else {
		Write-Logs "PASS" "README.txt" "README updates" "README.txt on desktop has been changed."
	}
	Copy-Item -Force $labReadme $logDir
	
	#$diff = Compare-Object (Get-Content $defaultReadme) (Get-Content $labReadme
	#If ( $diff ) {
	#} Else {
	#	Write-Logs "FAIL" "README.txt" "README updates" "No changes to README.txt on desktop."
	#}
} Else {
	Write-Logs "FAIL" "README" "README.txt" "Failed to find README.txt on desktop"
}

# look for anything called odyssey on the desktop
If ( $WMC ) {
	$desktopODY = "$mc/Users/Administrator/Desktop/*odyssey*"
} ElseIf ( $LMC ) {	
	$desktopODY = "$mc/home/holuser/Desktop/*odyssey*"
}
#Write-Host $desktopODY
If ( Get-ChildItem $desktopODY ) {
	Write-Logs "FAIL" "Core Team" "Odyssey" "Found Odyssey file on the desktop. Please remove. Client will be downloaded."
} Else {
	Write-Logs "PASS" "Core Team" "Odyssey" "No Odyssey files on the desktop. Client will be downloaded."
}

# look for BuildChecklist.txt on the desktop
If ( $WMC ) {
	$desktopChecklist = "$mc/Users/Administrator/Desktop/*Checklist*"
} ElseIf ( $LMC ) {	
	$desktopChecklist = "$mc/home/holuser/Desktop/*Checklist*"
}
#Write-Host $desktopChecklist
If ( Get-ChildItem $desktopChecklist ) {
	Write-Logs "FAIL" "Core Team" "BuildChecklist" "Found BuildChecklist.txt file on the desktop. This is for development only. Please remove."
} Else {
	Write-Logs "PASS" "Core Team" "BuildChecklist" "No BuildChecklist.txt  file on the desktop. Thanks!"
}
