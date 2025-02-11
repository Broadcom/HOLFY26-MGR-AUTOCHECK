# Report Card #23 All Windows OS firewalls disabled

$autocheckModulePath = "$PSSCriptRoot/autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$target = $hostname + "(" + $ipTarget + ")"	

# check if firewall off for all networks
$firewallScript = '"Powershell.exe -Command \"get-netfirewallprofile | select name,enabled\""'
Try {
	$errorVar = $null
	#Write-Host $firewallScript
	$wcmd = "/usr/bin/python3 runwincmd.py $ipTarget Administrator $password $firewallScript" | Set-Content "/tmp/runfw.sh"
	$output1 = Invoke-Expression -Command "/bin/sh /tmp/runfw.sh" -ErrorVariable errorVar
	#$output1 = RunWinCmd $firewallScript ([REF]$result) $ipTarget 'Administrator' $password
	
	$output1 = $output1.Replace('-', '')
	$output1 = $output1.Replace("['", '')
	$output1 = $output1.Replace("'']", '')
	$output1 = $output1.Replace("\r", '')
	$output1 = $output1.Replace("'", '')
	$output = $output1[0].Split(':')
	$fwConfig = $output[1].Split(',')
	Foreach ( $line in $fwConfig ) {
		If ($line -like '*True*' ) {
			$line = $line -replace '\s+', " "
			Write-Logs "FAIL" $target "Windows Firewall" "Windows machine $hostName has at least one active firewall. $line"
			Exit 0
		}
	}
} Catch {
	Write-Logs "FAIL" $target "Windows Firewall" "Cannot check Windows firewall on $hostname Is the firewall on?"
	Exit
}
Write-Logs "PASS" $target "Windows Firewall" "Windows machine $hostName has all firewall profiles off."
