Function Write-Logs ([string]$result, [string]$target, [string]$function, [string]$output) {
	#replace commas with dots so CSV format is good
	$target = $target -Replace ',', '.'
	$output = $output -Replace ',', '.'	
	Start-Sleep -Milliseconds 5 # get unique ID
	$timeStamp = Get-Date -Format "MM/dd/yyyy HH:mm:ss.fff" # unique time stamp
	$logEntry = "$timeStamp $vPodName $target $function $operation $result `n" + "$output`n"
	Write-Host $logEntry
} # End Write-Logs

Function VerifyDnsNameIP ( [string]$mName, [string]$ip, [string]$layer ) {
	$target = $mName + '(' + $ip + ')'
	Write-Host $target
	# check forward lookup
	#Write-Host "python3 nameip.py $mName"
	$output = Invoke-Expression "python3 nameip.py $mName"
	#Write-Host ".${output}."
	($dnsName, $dnsIP, $ipTmp) = $output.Split(":")
	If ( $dnsName -eq "unknown" ) {
		Write-Logs "WARN" $target "$layer DNS" "No DNS record found for $mName"
	} ElseIf ( $dnsIP -Like "*,*" ) {
		Write-Logs "WARN" $target "$layer DNS" "Multiple IP addresses found for $mName ${dnsIP}"
		If ( $ip -eq "unknown" ) { 
			$ips = $dnsIP.Split(',')
			$ip = $ips[0] # take the first DNS IP if $ip is unknown
		}
	} Else {
		Write-Logs "PASS" $target "$layer DNS" "Forward DNS lookup for ${mName}: ${dnsIP}"
		If ( $ip -eq "unknown" ) { $ip = $dnsIP }
	}
	
	# check reverse lookup
	#Write-Host "python3 nameip.py $ip"
	$output = Invoke-Expression "python3 nameip.py $ip"
	#Write-Host ".${output}."
	($dnsName, $dnsIP, $ip) = $output.Split(":")
	If ( $dnsName -eq "unknown" ) {
		Write-Logs "WARN" $target "$layer DNS" "No DNS record found for $ip"
		$dnsName = $mName # use the name as is.
	} ElseIf ( $dnsName -Like "*,*" ) { # WARN multiple hostnames for $ip
		Write-Logs "WARN" $target "$layer DNS" "Multiple host names found for $ip ${dnsName}"
		$dnsName = $mName # use the name provided (this is okay because we always use IP address for checks)
	} Else {
		Write-Logs "PASS" $target "$layer DNS" "Reverse DNS lookup for ${ipDNS}: ${mName}"
	}
	If ( $dnsIP -ne "unknown" ) { $target = $mName + '(' + $dnsIP + ')' }
	#Write-Host "dnsName: $dnsName mName: ${mName}.$dom"
	If ( $dnsIP -ne "unknown" ) {
		If ( $dnsName -ne "${mName}.$dom" -And $dnsName -ne $mName ) {
			Write-Logs "INFO" $target "$layer DNS" "Layer $layer machine ${mName}/$ip is different from DNS record $dnsName. Using DNS name."
		}
	}
	Return "${dnsName}:$dnsIP"
}

# establish the dom variable based on the current FQDN
$lcmd = "hostname -A" # 2024: change to hostname -A
$fqdn = Invoke-Expression -Command $lcmd
$i = $fqdn.IndexOf(".")
$hostname = $fqdn.SubString(0,$i)
$tl = $fqdn.length -1
$dl = $tl - $hostname.length
$dom = $fqdn.SubString($i+1,$dl)
$dom = $dom.Trim()

$result = ""

($nameIP) = VerifyDnsNameIP  "CB-01a" "10.0.0.221" "L1"

Write-Host "nameIP: $nameIP"
If ( $nameIP -ne $null ) {
	($dnsName,$dnsIP) = $nameIP.Split(":")
} Else {
	Write-Output "No DNS record."
}