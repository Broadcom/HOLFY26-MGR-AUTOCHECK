#62 Desktop shortcut names not truncated

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$target = $hostname + "(" + $ipTarget + ")"	

# get the names of the desktop shortcuts
If ( $ipTarge -eq "10.0.0.10" ) {
	$shortcutScript = 'Powershell.exe -Command `"Get-ChildItem C:\Users\Administrator\Desktop | select Name`"'
} Else {
	$shortcutScript = 'Powershell.exe -Command `"Get-ChildItem C:\Users\holuser\Desktop | select Name`"'
}	

# Windows desktop shortcuts with a file name (including the '.lnk' extension) longer than $maxLentgh will be truncated
$maxLength = 14
# only one log entry for long names per machine
# check the holuser account - must use Administrator account
# check the WMC directly using the /wmchol share
$longShortcuts = ''
Try {
	$errorVar = $null
	$output1 = RunWinCmd $shortcutScript ([REF]$result) $ipTarget 'Administrator' $password 2>&1
	$output1 = $output1.Replace("-", "")
	$output1 = $output1.Replace("', '", "")
	$output1 = $output1.Replace("['", "")
	$output = $output1.Split("\r")
	$flag = $false
	ForEach ( $line in $output ) {
		$line = $line.Trim()
		If ( $flag -And $line.Length -gt 14 ) { $longShortcuts = $line }
		If ( $line -eq "Name" ) { $flag = $true }
	}
} Catch {
	Write-Logs "FAIL" $target "Windows Desktop Shortcuts" "Cannot check Windows Desktop Shortcuts on $hostname. $errorVar"
}
#Write-Output $urls
If ( $longShortcuts ) {
	Write-Logs "WARN" $target "Windows Desktop Shortcuts" "Windows Desktop Shortcut with long name on $hostname. The name should be less than 15 characters: $longShortcuts"
} Else {
	Write-Logs "PASS" $target "Windows Desktop Shortcuts" "Windows Desktop Shortcuts look good on $hostname. Thanks!"
}

