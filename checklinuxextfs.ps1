# checklinuxextfs.ps1 16-April 2024

# need this stuff at a minumum
# LMC updates with plink July 24, 2021
# dealing with a remote error June 4, 2023

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

$hostName = $args[0]
$ipTarget = $args[1]

$target = $hostname + "(" + $ipTarget + ")"

# create the File Systems command using "here" command syntax so Linux pipe can be sent literally
<# $fsCmd = @"
"cat /proc/mounts | grep ext[234] | cut -f 1 -d ' '"
"@
#>

$fsCmd = @"
"mount | grep ext[234] | cut -f 1 -d ' '"
"@

# DEBUG
Write-Output "check EXT FS on $hostname $ipTarget"

$continue = $true

$output = $null
$raw = remoteLinuxCmdLMC $ipTarget $linuxuser $linuxpassword $fsCmd
ForEach ( $line in $raw ) {
	[String]$entry = $line
	If ( $entry.StartsWith('/dev/' ) ) { $output += "$entry " }
}
If ( $output -ne $null ) { $output = $output.TrimEnd() }
If ( $LASTEXITCODE -ne 0 ) { $errorVar = $output }


If ( $output -eq $null ) {
	$continue = $false # nothing to check
	Write-Logs "PASS" $target "EXT FS" "No file systems to check on $hostName"
}
If ($errorVar -ne $null -And $continue ) {
	$continue = $false # no access cannot check
	[String]$error = $errorVar
	$error = $error.Trim() # remove the newline
	Write-Logs "FAIL" $target "EXT FS" "Cannot check file systems on $hostName $error"
}

If ( $continue ) {
	Try {
		$fsToCheck = $output.split(' ')
	} Catch {		
		# if we're here, there was probably a remote error so try using the last element in $output
		$fsToCheck = $output[$output.Length - 1].Split(' ')
	}
	$prevFs = "junk"
	$fsArray = $fsToCheck.Split()
	Foreach ($fs in $fsArray) {
		$fs = $fs.Trim()
		If ( $fs -eq $prevFs ) { Continue } # no need to check duplicates
		$errorVar = $null
		$output = $null
		$fsCmd2 = @"
"dumpe2fs $fs 2>&1 | grep -v dumpe2fs | grep ^Maximum; dumpe2fs $fs 2>&1 | grep -v dumpe2fs | grep -i interval"
"@
		$raw = remoteLinuxCmdLMC $ipTarget $linuxuser $linuxpassword $fsCmd2
		$raw | Set-Content "/tmp/extfs.out"
		ForEach ( $line in Get-Content "/tmp/extfs.out" ) {
			If ( $line -Like "*Maximum mount count:*" ) { 
				#Write-Host "found Maximum mount count"
				$output += "$line "
			} ElseIf ( $line -Like "*check interval:*" ) {
				#Write-Host "found check interval"
				$line = $line.Replace('(', '')
				$line = $line.Replace(')', '')
				$output += "$line " 
			}
		}
		If ( $LASTEXITCODE -ne 0 ) { $errorVar = $output }
		
		#Write-Host "output: $output"
		
		If ( $errorVar -ne $null -Or ($output -eq "") ) {
			Write-Logs "FAIL" $target "EXT FS" "Cannot check file system $fs on $hostName $errorVar"
		} Else { # match output for no fsck checks
			$output = $output -replace '\s+', " "
			If ( ($output -like '*Maximum mount count:*-1*') -And ( $output -like '*check interval:*0*' ) ) {
				Write-Logs "PASS" $target "EXT FS" "File system $fs result on $hostName $output"
			} Else {
				Write-Logs "FAIL" $target "EXT FS" "File system $fs result on $hostName $output"
			}
		}
		$prevFs = $fs
	}
}
If ( Test-Path "/tmp/extfs.out" ) { Remove-Item -Force "/tmp/extfs.out" }


