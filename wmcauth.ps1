
$ipTarget = $args[1]
$user = $args[2]
$plinkPath = "C:\'Program Files'\PuTTY\plink.exe"
$wcmd = "Echo Y | $plinkPath -ssh $ipTarget -l $user date  2>&1" # check ssh auth for root first
$output = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
If ( $errorVar -ne $null ) {
	Write-Output "FALSE"
} Else {
	Write-Output "TRUE"
}