# Report Card #46 passwords set to NEVER expire

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$domain = $args[2]
$target = $hostname + "(" + $ipTarget + ")"

If ( $domain ) {
	# TODO: get the list of domain accounts
	$pwCmd = "net user /domain"
} Else {
	# get the list of local accounts
	$pwCmd = "net user"
}
$output1 = RunWinCmd $pwCmd ([REF]$result) $ipTarget 'Administrator' $password
$output1 = $output1.Replace("-", "")
$output1 = $output1.Replace("', '", "")
$output1 = $output1.Replace("['", "")
$out = $output1.Split("\r")
$accounts = @()
Foreach ($line in $out) {
	If ( $line -Like "*User accounts for*" ) { Continue }
	If ( $line -Like "" ) { Continue }
	If ( $line -Like "*The command completed*" ) { Continue }
	If ( $line -Like "*']*" ) { Continue }
	($accountName, $junk) = $line.Split()
	If ( $accountName -ne "" ) { $accounts += $accountName }	
}

# check the password expiration for each local account
Foreach ($account in $accounts) {
	$wcmd = "net user $account"
	$output1 = RunWinCmd $wcmd ([REF]$result) $ipTarget 'Administrator' $password
	$output1 = $output1.Replace("-", "")
	$output1 = $output1.Replace("', '", "")
	$output1 = $output1.Replace("['", "")
	$output = $output1.Split("\r")
	Foreach ($line in $output) {
		#Write-Host $line
		If ( $line -like '*Account active*' ) {
			($f1, $f2, $active) = $line.Split()
		}
		If ( $line -like '*Password expires*' ) {
			If ( $line -like '*Never*' ) {
				Write-Logs "PASS" $target "Windows $domain account $account password expiration" "$domain Account $account password on $hostName never expires."
				Break
			} Else {
				If ( $active -Like "*Yes*" ) {
					Write-Logs "FAIL" $target "Windows $domain account $account password expiration" "$domain Account $account on $hostName $line"
				} Else { 
					Write-Logs "PASS" $target "Windows $domain account $account password expiration" "Inactive $domain Account $account on $hostName $line"
				}
			}
		}
	}
	
}

# End check Windows Passwords expiration
