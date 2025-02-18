# puttysessions.ps1 version 1.0 29-March 2024

# machines to be added to $linuxMachines hash
$out = "C:\hol\puttysessions.txt"
Set-Content -Path $out -Value "" -NoNewline

# PuTTY variables
$puttyPath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
$puttySessions = Get-ChildItem $puttyPath

Foreach ($session in $puttySessions) {
	#Write-Output "Checking $session..."
	#$ps = New-Object -TypeName psobject
	If ( $session -Like '*Default*') { Continue }	# skip Default
	#Write-Host "session: $session"
	$puttyHost = ""
	$puttyIP = ""
	$parts = ($session.Name).split('\')
	$sessionName = $parts[$parts.length-1] # use the last part of the Registry key
	$hostName = $session.getValue('HostName')
	#Write-Host "hostName: $hostName"

	If ( $hostName -Like '*@*' ) { 
		($puttyUserName, $puttyHost) = $hostName.Split('@') # if $account - correct HOL convention
		#Write-Host "puttyHost: $puttyHost"
	} Else {		
		$puttyHost = $hostName
		$puttyUnProperty = Get-ItemProperty -Path "$puttyPath\$sessionName" -Name "UserName"
		$puttyUserName = $puttyUnProperty.UserName # if puttyUserName - incorrect HOL convention but acceptable (if neither - FAIL)
	}
	"$hostName~$puttyUserName" | Add-Content $out
}