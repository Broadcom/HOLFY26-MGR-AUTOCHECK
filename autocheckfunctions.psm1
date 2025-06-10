<#
	Autocheck Functions *Module* for VMware Hands-on Labs
	
	AutoCheckfunctions.psm1 - version 2.5.1 - 30-May 2025
	
	Support only running from the Manager VM

#>


#### HOL Variables ####

$result = ''

# some things are different depending on the version of PowerShell
$psVersion = $PSVersionTable.PSVersion.Major
Export-ModuleMember -Variable psVersion

# some checks require PowerShell to be run in a separate instance
$powerShell = "pwsh"
Export-ModuleMember -Variable powerShell

# used in remoteLinuxCmdLMC and scpLMC functions
$sshPass = '/usr/bin/sshpass'
Export-ModuleMember -Variable sshPass
$sshOptions = '-o StrictHostKeyChecking=accept-new'
Export-ModuleMember -Variable sshOptions

# establish the dom variable based on the current FQDN
$lcmd = "hostname -A" # 2024: change to hostname -A
$fqdn = Invoke-Expression -Command $lcmd
$i = $fqdn.IndexOf(".")
$hostname = $fqdn.SubString(0,$i)
$tl = $fqdn.length -1
$dl = $tl - $hostname.length
$dom = $fqdn.SubString($i+1,$dl)
$dom = $dom.Trim()
Export-ModuleMember -Variable dom

# Core Team machine IP addresses
$mcIP = "10.1.10.130"
Export-ModuleMember -Variable MCip

$rtrIP = "10.1.10.129"
Export-ModuleMember -Variable MCip

# TODO: confirm this IP
$stgIP = "10.1.1.3"
Export-ModuleMember -Variable stgIP

$mgrIP = "10.1.10.131"
Export-ModuleMember -Variable mgrIP

# need to know if WMC or LMC
If ( Test-Path "/lmchol/home/holuser" ) {
	$LMC = $true
	$mc = "/lmchol"
	$mcTmp = "${mc}/tmp"
	$WMC = $false
} ElseIf ( Test-Path "/wmchol/hol" ) {
	$WMC = $true
	$mc = "/wmchol"
	$mcTmp = "${mc}/Temp"
	$LMC = $false
	$plinkPath = "C:\'Program Files'\PuTTY\plink.exe"
}
$mcholroot = "$mc/hol"
Export-ModuleMember -Variable LMC
Export-ModuleMember -Variable WMC
Export-ModuleMember -Variable mc
Export-ModuleMember -Variable mcholroot
Export-ModuleMember -Variable mcTmp

$TMPlogDir = "/tmp"
New-Item -Path $TMPlogDir -Name "AutoCheck" -ItemType "directory" -Force
$logDir = Join-Path -Path $TMPlogDir -ChildPath "AutoCheck"
Export-ModuleMember -Variable logDir

($junk, $vpod_sku) = (Get-Content $TMPlogDir/vPod.txt -First 1).Split('=')
($junk, $lab_sku) = $vpod_sku.Split('-')
$year = $lab_sku.Substring(0, 2)
Export-ModuleMember -Variable lab_sku
Export-ModuleMember -Variable year


# the path to the "resource" files that contain the vCenters, hosts, services, etc.
$resourceFileDir = "/vpodrepo/20${year}-labs/$lab_sku"
Export-ModuleMember -Variable resourceFileDir

$configIni = "${resourceFileDir}/config.ini"
Export-ModuleMember -Variable configIni

# get vAppName from vAppName.txt (lowercase for Linux)
$vAppNameFile = Join-Path -Path $resourceFileDir -ChildPath "vappname.txt"
Export-ModuleMember -Variable vAppNameFile
If ( Test-Path $vAppNameFile ) {
	$vPodName = Get-Content -Path $vAppNameFile
	Export-ModuleMember -Variable vPodName
}

# Credentials used to log into vCenters
# vcuser could be "root" if using ESXi host only
$vcusers = ("Administrator@$dom",'Administrator@vsphere.local', 'Administrator@vsphere2.local', 'Administrator@regiona.local', 'Administrator@regionb.local')
Export-ModuleMember -Variable vcusers

# get the password from ~holuser/creds.txt
$password = Get-Content '/home/holuser/creds.txt' -First 1
Export-ModuleMember -Variable password

$rtrpassword = Get-Content '/home/holuser/rtrcreds.txt' -First 1
Export-ModuleMember -Variable rtrpassword

# Credentials used to log into Linux machines
$linuxuser = 'root'
$linuxpassword = $password
Export-ModuleMember -Variable linuxuser
Export-ModuleMember -Variable linuxpassword

# Credentials used to log in to NSX Manager machines
$nsxuser = 'admin'
$nsxpassword = $password
Export-ModuleMember -Variable nsxuser
Export-ModuleMember -Variable nsxpassword

# vROPs and NSX-T API returns license expiration date based on Unix Epoch
$epoch = Get-Date -Date "01/01/1970"
Export-ModuleMember -Variable epoch

# calculate expiration date based on the year of $vPodName.
If ( $vPodName -ne $null ) {
	#$vPodYear = $vPodName.substring(4,2)
	$vPodYear = $year
	Export-ModuleMember -Variable vPodYear
	$expirationDate = "12/31/20${vPodYear}"
	Export-ModuleMember -Variable  expirationDate

	$licenseExpireDate = Get-Date "$expirationDate 12:00:00 AM"
	Export-ModuleMember -Variable  licenseExpireDate

	$chkDateMin = $licenseExpireDate.AddDays(-30)
	Export-ModuleMember -Variable  chkDateMin
	
	# minimim date for 90-day evaluation licenses (good through Explore US) 
	$chkDateMin90 = "08/30/20${vPodYear}"
	Export-ModuleMember -Variable  chkDateMin90
	
	$chkDateMax = $licenseExpireDate.AddDays(30)
	Export-ModuleMember -Variable  chkDateMax

	# for SSL certificate checking
	$minValidDate = [datetime]$expirationDate
	Export-ModuleMember -Variable minValidDate
}

# sleep time between checks, in seconds
$sleepSeconds = 2
Export-ModuleMember -Variable sleepSeconds

# layer 1 storage utilization to avoid shadow exports
$storagethreshold = 50
Export-ModuleMember -Variable storagethreshold

# the IP addresses to choose as $ipTarget in Choose-IP function
# Communication is allowed only among RFC 1918 networks:
#192.168.0.0/16
#172.16.0.0/12 07/08/2020 expanding to 172.0.0.0/8
#10.0.0.0/8
$ipPatterns = @('10.*.*.*',
				'172.*.*.*',
				'192.168.*.*')
Export-ModuleMember -Variable ipPatterns

# 2024: just use "ntp" and depend on DNS resolution
# allowed NTP time source patterns array
$timeSources = @('*10.1.1.1*',
				'*ntp*',
				'*router*',
				'*10.1.10.129*')
Export-ModuleMember -Variable timeSources

$dnsForwarders = @('*8.8.8.8*',
				'*8.8.4.4*',
				'*10.0.0.221*')
Export-ModuleMember -Variable dnsForwarders

# must use lowercase file name for Linux
# 2024: use vpodrepo
$layerOneInfo = Join-Path -Path $resourceFileDir -ChildPath "layeroneinventory.txt"
Export-ModuleMember -Variable layerOneInfo

# path to log files
$csvFile = Join-Path  $logDir "autocheck-$vPodName.csv"
Export-ModuleMember -Variable csvFile
$csvDetailFile = Join-Path  $logDir "autocheck-detail-$vPodName.csv"
Export-ModuleMember -Variable csvDetailFile
$logFile = Join-Path $logDir "autocheck-$vPodName.log" # could eliminate if we remove commas from $output
Export-ModuleMember -Variable logFile

## File and executable paths
# Set the root of the execuatable path
$labStartupRoot = '/home/holuser/hol'  # 2024: running on Manager
Export-ModuleMember -Variable labStartupRoot


#this file is used to report status via DesktopInfo
$statusFile = Join-Path $mcholroot 'startup_status.txt'
Export-ModuleMember -Variable statusFile
# handy match pattern to determine if we're dealing with a host name or an IP address
$IPRegex = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$"
Export-ModuleMember -Variable IPRegex

#### Internal variables ####

#must be defined in order to pass as reference for looping
$result = ''

Function Write-Logs ([string]$result, [string]$target, [string]$function, [string]$output) {
	#replace commas with dots so CSV format is good
	$target = $target -Replace ',', '.'
	$output = $output -Replace ',', '.'	
	Start-Sleep -Milliseconds 5 # get unique ID
	$timeStamp = Get-Date -Format "MM/dd/yyyy HH:mm:ss.fff" # unique time stamp
	$csvEntry = "$timeStamp,$vPodName,$target,$function,$result"
	$csvEntry | Add-Content $csvFile
	$csvDetailEntry = "$timeStamp,$vPodName,$target,$function,$result,$output"
	$csvDetailEntry | Add-Content $csvDetailFile
	$logEntry = "$timeStamp $vPodName $target $function $operation $result `n" + "$output`n"
	$logEntry | Add-Content $logFile -NoNewLine
	Start-Sleep -Milliseconds 5
} # End Write-Logs
Export-ModuleMember -Function Write-Logs

Function Read-FileIntoArray {
<#
	Read contents of a text file and return as an array, each line is an item
	Skip lines beginning with "#" as they are assumed to be comments
#>
	PARAM ( [string]$fileName ) 
	PROCESS {
		$theData = @()
		$filePath = Join-Path $resourceFileDir "$fileName.txt"
		If( Test-Path $filePath ) {
			(Get-Content $filePath) | % {
				$line = $_
				if( ($line -notlike "#*") -and ($line -notlike "") ) {
					$theData += $line
				}
			}
		}
		return $theData
	}
} #END Read-FileIntoArray
Export-ModuleMember -Function Read-FileIntoArray

Function Read-ConfigIntoArray {
<#
	Skip lines beginning with "#" as they are assumed to be comments
#>
	PARAM ( 
		[string]$section,
		[string]$item
	)
	PROCESS {
		$theData = @()
		If ( -Not ( Test-Path $configIni ) ) {
			Write-Output "$configIni NOT FOUND! Abort."
			Exit 1
		}
		$sectionFound = $false
		$itemFound = $false
		#$nextSection = $false
		$lines = Get-Content $configIni
		# -Or ( $line -NotLike "" ) )
		ForEach ( $line in $lines ) {
			If ( ( $line -NotLike "*#*" ) -And ( $line -NotLike "" ) ) {
				If ( ( $line -Like "* = *" ) -And ( $itemFound ) ) { break }
				If ( ( $line -Like "[*]" ) -And ( $itemFound ) ) { break }
				If ( ( $sectionFound ) -And ( $line -Like "*${item} =*" ) ) {
					$itemFound = $true
					($junk, $line) = $line.Split('=')
					$theData += $line.Trim()
				} ElseIf ( $itemFound -And ( $line -NotLike '`[*`]' ) ) { # do not include the next section
					$theData += $line.Trim()
				} ElseIf ( ( $line -Like "*[${section}]*" ) -And ( -Not $sectionFound ) ) {
					$sectionFound = $true
				}
			}
		}
		return $theData
	}
} #END Read-ConfigIntoArray
Export-ModuleMember -Function Read-ConfigIntoArray

Function Connect-VC ([string]$server, [string]$username, [string]$password, [REF]$result) {
<#
	This function attempts once to connect to the specified vCenter 
	It sets the $result variable to 'success' or 'fail' based on the result
#>
	Try {
		Connect-ViServer -server $server -username $username -password $password -ErrorAction 1 | Out-Null
		#$version = $vc.Version
		#$build = $vc.Build
		#Write-Host "version: $version build: $build"
		#Write-Logs "INFO" $server "vCenter build" "$server running version $version build $build" 
		#Write-Host "$server connection successful"
		$result.value = "success"
	}
	Catch {
		return $_.Exception.Message
		#Write-Logs "FAIL" $server "vCenter connection" "Failed to connect to server $server $_.Exception.Message"
		#Write-Host $_.Exception.Message
		$result.value = $false
	}
} #End Connect-VC
Export-ModuleMember -Function Connect-VC

# 01/30/2021 works in PowerShell 5 but not in PowerShell 7
function ConvertFrom-Json20([object] $item){
	#http://stackoverflow.com/a/29689642
	Add-Type -AssemblyName System.Web.Extensions
	$ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
	#The comma operator is the array construction operator in PowerShell
	return ,$ps_js.DeserializeObject($item)
} # End ConvertFrom-Json20
Export-ModuleMember -Function ConvertFrom-Json20

Function Check-DHCP ([string]$ip) {
	($o1,$o2,$o3,$o4) = $ip.Split('.')
	$subnet = $o1 + '.' + $o2 + '.' + $o3
	#Write-Host "subnet: $subnet"
	If ( ($subnet -eq "10.0.100") -or ($subnet -eq "10.0.131") `
	 -or ($subnet -eq "192.168.140") -or ($subnet -eq "192.168.150") `
	 -or ($subnet -eq "192.168.240") -or ($subnet -eq "172.16.254" ) ) {
		If ( ([int]$o4 -gt 99) -and ([int]$o4 -lt 251) ) {
		 #Write-Host "$ip is in known DHCP range."
		 Return $true
		} Else { Return $false }
	} Else { Return $false } # IP address is NOT in a known DHCP subnet
} #End Check-DHCP
Export-ModuleMember -Function Check-DHCP

Function Test-TcpPortOpen ([string]$Server, [int]$Port, [REF]$Result) {
<#
	This function makes sure a host is listening on the specified port
	It does not attempt to validate anything beyond a simple response
	It sets the $result variable to 'success' or 'fail' based on the result
#>
	Try {
		$requestCallback = $state = $null
		$socket = New-Object Net.Sockets.TcpClient
		$beginConnect = $socket.BeginConnect($Server,$Port,$requestCallback,$state)
		#$socket.Connect($Server,$Port)
		Start-Sleep -milli 500
		if($socket.Connected) { 
			Write-Host "Successfully connected to server $Server on port $Port"
			$Result.value = "success"
		} Else { $Result.value = "fail" }
		$socket.Close()
		
	}
	Catch {
		#Write-Host "Failed to connect to server $Server on port $Port"
		$Result.value = "fail"
	}
} #End Test-TcpPortOpen
Export-ModuleMember -Function Test-TcpPortOpen

Function Choose-IP ([Array]$IPs) {
	#Write-Output $IPs "Choose-IP"
	# choose the 192.168.*.* IP FIRST if available
	Foreach ( $ip in $IPs ) {
		If ( $ip -eq '192.168.0.2' ) { Continue }
		If ( $ip -Like "10.*.*.*") { Return $ip }
	}
	# Else choose the next best IP
	Foreach ( $ip in $IPs ) {
		#Write-Host "Choose-IP: $ip ."
		If ( $ip -Like '*::*' ) { Continue } # ipv6
		If ( $ip -match '169.254.*' ) { Continue } # unassigned
		ForEach ($pattern in $ipPatterns){
			#Write-Host "$ip $pattern"
			If ( $ip -Like "$pattern*" ) {
				#Write-Host "match"
				Return $ip
			}
		}
	}				
} #End Choose-IP
Export-ModuleMember -Function Choose-IP

Function Choose-TimeSource ( [Array]$sources) {
	ForEach ( $source in $sources ) {
		ForEach ($pattern in $timeSources){
			# Write-Host "pattern: $pattern source: $source"
			If ( $source -Like "*$pattern*" ) {
				Return $source
				Break
			}
		}
	}
	If ( $sources -Like "*no such*" ) { Return "notfound" }
	If ( $sources -Like "*not found*" ) { Return "notfound" }
	Return "invalid"
} #End Choose-TimeSource
Export-ModuleMember -Function Choose-TimeSource

Function VerifyDnsNameIP ( [string]$mName, [string]$ip, [string]$layer ) {
	$target = $mName + '(' + $ip + ')'
	#Write-Host $target
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
		$target = "${mName}(${dnsIP})"
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
		Write-Logs "PASS" $target "$layer DNS" "Reverse DNS lookup for ${dnsIP}: ${mName}"
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
Export-ModuleMember -Function VerifyDnsNameIP

# vCloud Director variables and functions
$apiVersion = ''
Export-ModuleMember -Variable apiVersion
$vCDTokenType = ''
Export-ModuleMember -Variable vCDTokenType
$VCDToken = ''
Export-ModuleMember -Variable vCDToken

function Call-VCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$tokenType=$vCDTokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$token=$vCDToken,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		$url,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$requestType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$apiVersion,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$contentType='application/*+xml',
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$body,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$inFile
	)
	
	$optionalParams = @{}
	if($Body) {
		$optionalParams["Body"] = $body
	}
	if($InFile) {
		$optionalParams["InFile"] = $inFile
	}
	
	try {
		return Invoke-RestMethod -NoProxy -Method $requestType -Uri $url -Headers @{Authorization = "$tokenType $Token"; Accept = "application/*+xml;version=$apiVersion" } -ContentType $contentType @optionalParams
	}
	catch {
		Write-Host $_.Exception.Response.RequestMessage
	}
} # end Call-VCD
Export-ModuleMember -Function Call-VCD

function LogOffFromVCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$server,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$tokenType=$vCDTokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$token=$vCDToken,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$apiVersion
	)
	
	$url =	"https://$Server/api/session"
	Call-VCD -RequestType "DELETE" -TokenType $tokenType -Token $token -Url $Url -ApiVersion $apiVersion | Out-Null
	
	if( (-not ([string]::IsNullOrEmpty($vCDServer) ) ) -and ( $vCDServer -eq $server) )	{
		$vCDToken = $null
		$vCDTokenType = $null
		$vCDServer = $null
	}
	
} # end LogOffFromVCD
Export-ModuleMember -Function LogOffFromVCD

function LogOnToVCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$userName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$orgName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$password,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$server,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$apiVersion
	)
	
	$vcduser = "${userName}@${orgName}"
	$baseUrl = "https://$server/api"
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${vcduser}:${password}"))
	$auth = "Basic $base64AuthInfo"
	$accept = "application/*;version=$apiVersion"
	$type = "application/xml"
	$headers = @{ Authorization = $auth; Accept = $accept }
	try {
		$response = Invoke-WebRequest -Method 'POST' -Uri "${baseUrl}/sessions" -Headers $headers -ContentType $type -ErrorVar errorVar
		Write-Host "response: $response"
		if( (-not ([string]::IsNullOrEmpty($global:VCDServer) ) ) -and ( $global:VCDServer -ne $Server) )	{
			Write-Output "Connected to multiple servers in a single context! Currently $Server data is stored globally!"
		}
		$vCDToken = $response.Headers["X-VMWARE-VCLOUD-ACCESS-TOKEN"]
		$vCDTokenType = $response.Headers["X-VMWARE-VCLOUD-TOKEN-TYPE"]
		$vCDServer = $server
		#$vCDQueryUrl = "https://$Server/api/query"
		#if($apiVersion -ne $vCDApiVersion) {
		#	$global:VCDApiVersion = $apiVersion
		#}
	}
	catch {
		Write-Host "errorVar: $errorVar"
	}
	
	return @{ "tokenType" = $($response.Headers["X-VMWARE-VCLOUD-TOKEN-TYPE"]); "token" = $($response.Headers["X-VMWARE-VCLOUD-ACCESS-TOKEN"]); }
} # end LogOnToVCD
Export-ModuleMember -Function LogOnToVCD

function Get-VCDData {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$TokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$Token,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Url,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ContentType='application/*+xml',
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion
	)
	$ret = Call-VCD -RequestType "GET" -TokenType $TokenType -Token $Token -Url $Url -ApiVersion $ApiVersion -ContentType $ContentType
	if($ret) {
		return $ret.SelectSingleNode("/*")
	} else {
		throw "GET to $Url returned NULL value"
	}
} # end Get-VCDData
Export-ModuleMember -Function Get-VCDData

Function RunWinCmd ([string]$wcmd, [REF]$result, [string]$remoteServer, [string]$remoteUser, [string]$remotePass) {
<#
  Execute a Windows command on the local machine with some degree of error checking
  REQUIRES Python script runwincmd.py
#>
	$errorVar = ""
	
	# need this in order to capture output but make certain not already included
	if ( !($wcmd.Contains(" 2>&1")) -And !($remoteServer) ) {
		  $wcmd += ' 2>&1'
	}
	
	If ( $remoteServer ) {
		If ( -Not $remoteUser ) { $remoteUser = $vcuser }
		If ( -Not $remotePass ) { $remotePass = $password }		
		$wcmd = "/usr/bin/python3 runwincmd.py $remoteServer $remoteUser $remotePass `"$wcmd`""
	}
	#Write-Host "wcmd: $wcmd"
	$output = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	#Write-Host $output
	
	if ( $errorVar.Length -gt 0 ) {
		#Write-Host "Error: $errorVar"
		$result.Value = "fail"
		return $errorVar
	} else {
		ForEach ( $line in $output ) {
			#Write-Host ".${line}."
			If ( $line -Like "*Running*" ) { Continue }
			If ( $line -Like "*pinged*" ) { Continue }
			If ( $line -Like "*success*" ) { Continue }
			($junk, $output) = $line.Split(":")
		}
		$result.Value = "success"
		return $output
	}
} #End RunWinCmd
Export-ModuleMember -Function RunWinCmd

Function cleanupWindowsOutput {
	[CmdletBinding()]
	PARAM([string]$intext)
	PROCESS {
		$output = @()
		$work = $intext.Split("`r`n")
		Foreach ( $line in $work ) {
			$line = $line.Replace('[', '')
			$line = $line.Replace('\r', '')
			$line = $line.Replace(']', '')
			$line = $line.Replace("`'", "")
			$line = $line.Replace(',', '')
			$line = $line.Replace('name', '')
			$line = $line.Replace('Enabled', '')
			$line = $line.Replace('-', '')
			#Write-Host "line: $line"
			$output += $line
		}
		Return $output
	}
} # end cleanupWindowsOutput
Export-ModuleMember -Function cleanupWindowsOutput

# 2024 - move this to scripts that run locally on the Main Console
# checkbrowsers.ps1 and checkurls.ps1
If ( $WMC ) {
	If ( Test-Path "$mcholroot/run.ps1" ) { Remove-Item "$mcholroot/run.ps1" }
	# get the default browser
	$regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
	"Get-ItemPropertyValue -Path $regPath -Name `"ProgId`"" | Set-Content -Path "$mcholroot/run.ps1"
	$wcmd = "pwsh -File C:\hol\run.ps1"
	$regBrowser = RunWinCmd $wcmd ([REF]$result) 'mainconsole' 'Administrator' $password
	If ( $regBrowser -Like "*Firefox*" ) {
		$browser = "Firefox"
	} Else {
		$browser = "Chrome"
	}
} ElseIf ( $LMC ) { $browser = "Firefox" }
Export-ModuleMember -Variable browser

Function Test-URL { 
	[CmdletBinding()] 
	PARAM(
		[string]$Url,
		[REF]$Result
	)
	
	PROCESS {
<#
	This function accesses the specified URL.
	It sets the $result variable to 'success' or 'fail' based on the result 
	
	NOTE: will use the system-configured proxy by default. To change this,
	$wcli.Proxy = New-Object System.Net.WebProxy("http://proxy:3128",$true)
	
	EXAMPLE:
		$url = 'https://pulseapi.vcf.sddc.lab/api/docs/index.html'

		Test-URL -Url $Url -Result ([REF]$result)
#>
		$sp = [System.Net.ServicePointManager]::SecurityProtocol
			
		#ADD TLS1.2 to the default (SSLv3 and TLSv1)
		[System.Net.ServicePointManager]::SecurityProtocol = ( $sp -bor [System.Net.SecurityProtocolType]::Tls12 )
		
		#Disable SSL validation (usually a BAD thing... but this is a LAB)
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		
		Try {
			$wcli = (New-Object Net.WebClient)
			$wc = $wcli.DownloadString($Url)
			$Result.value = "success"

		}
		Catch {
			Write-Output "URL $url not accessible"
			Write-Output "Error occured: $_"
			$Result.value = "fail"
		}
		#Reset default SSL validation behavior
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
	}

} #End Test-URL
Export-ModuleMember -Function Test-URL

# 7/16/2020 check Core Team version (can be used more if standard version string is used)
Function checkCTVersion ( [String]$srcFile, [DateTime]$versionDate ) {
	$source = Get-Content $srcFile
	ForEach ( $line in $source ) {
		If ( $line -Like "*version*" ) {
			If ( $line -Like "*-*" ) {
				$parts = $line.Split('-')
				If ( $parts.Length -eq 4 ) { 
					$dateString = $parts[2] + $parts[3]
				} ElseIf ( $parts.Length -eq 3 ) {
					If ( $parts[1] -Like "*version*" ) {
						$dateString = $parts[2]
					} Else { $dateString = $parts[1] + $parts[2] }
				} ElseIf ( $parts.Length -eq 2 ) {
				 	If ( $parts[0] -Like "*version*" ) {
				 		$day = $parts[0].Substring($parts[0].Length-2)
				 		$dateString = $day + $parts[1]
				 	}
				} Else {
					$dateString = $parts[2]
				}
				$dateString = $dateString + " 12:00:00 AM"
			} Else {
				$p = $line.Split(" ")
				$dateString = $p[$p.Count - 3] + " " + $p[$p.Count - 2] + " " + $p[$p.Count - 1] + " " +  "12:00:00 AM"
			}
			#Write-Host $dateString
			$sourceDate = Get-Date $dateString
			If ( $sourceDate -ge $versionDate ) {
				Write-Logs "PASS" "Core Team" $srcFile "$srcFile version is good: $sourceDate"
			} Else {
				Write-Logs "FAIL" "Core Team" $srcFile "$srcFile version is bad: $sourceDate needs update to: $versionDate"
			}
			Break
		}
	}
} #End checkCTVersion
Export-ModuleMember -Function checkCTVersion

# 8/13/2020 move repetitive snap code from main block
Function createSnap {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$vmName
	)
	# create a snapshot so we can revert safely without worrying about remote access or VM Tools.
	# delete previous autocheck snapshots if present (helpful in testing and development)
	$vm = Get-VM -Name $vmName
	$snaps = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
	Foreach ( $snap in $snaps ) { 
		Try {
			$junk = Remove-Snapshot -Snapshot $snap -Confirm:$false -ErrorAction SilentlyContinue
		} Catch {
			Write-Host "Cannot remove snapshot $snap."
		}
	}
	$snapError = ''
	Try {
		$snap = New-Snapshot -VM $vm -Name "autocheck" -ErrorVariable snapError -ErrorAction SilentlyContinue
		If ( $snapError ) {
			Write-Host "Cannot create snapshot on $vm. $snapError"
			Write-Logs "INFO" $vm "Windows Checks" "$vm is controlled by solution. Please check manually. $snaperror"
			Return $false
		} Else { Return $true }
	} Catch {
		Write-Host "Cannot create snapshot on $vm. $snapError"
		Return $false
	}
} # end CreateSnap
Export-ModuleMember -Function createSnap

# 8/14/2020 move repetitive L2 start code from main block
Function start-L2 {
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$vmName
	)
	
	BEGIN {
		createSnap $vmName
		$vm = Get-VM -Name $vmName
	}
	
	PROCESS {
		If ( $vm.guest.ToolsVersion -ne "") { # if we have VM Tools
			$vm = Start-VM -VM $vm -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable startError | Wait-Tools -TimeoutSeconds 60 -ErrorAction SilentlyContinue
			$vm = Get-VM -Name $vmName
			If ( $vm.PowerState -eq "PoweredOff" ) {
				Write-Host "Unable to power on $vmName $startError"
				Return $false
			}
			$vm = Get-VM -Name $vmName  # re-check for IP
			$ipCtr = 0
			While ( -Not $vm.Guest.IPAddress ) {
				$vm = Get-VM -Name $vmName
				
				# DEBUG
				#$ip = $vm.Guest.IPAddress
				#Write-Output "$vmName vm.Guest.IPAdrress "  $vm.Guest.IPAddress
				
				If ( $ipCtr -ge 5 ) { 
					Write-Host "$vmName no IP Address after waiting. $ipCtr"
					Return $false
				}
				Start-Sleep 5
				$ipCtr++
			}
			Return $true
		} Else {
			Try {
				$junk = Start-VM -VM $vm -Confirm:$false -ErrorAction SilentlyContinue # no VM Tools so hope reverse DNS finds the IP.
			} Catch {
				Write-Host "Cannot start $vmName."
				Return $false
			}
		}
	}
} # end function start-L2
Export-ModuleMember -Function start-L2

# 8/14/2020 move repetitive L2 IP code from main block
Function get-L2-IP {
	[CmdletBinding()]
	PARAM (
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$vmName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$osType  # Linux or Windows
	)
	
	BEGIN {
		$vm = Get-VM -Name $vmName
	}
	
	PROCESS {
		If ( $vm.Guest.IPAddress ) {  # this implies VM TOols are present
			$vmIPs = @() # Choose-IP needs an array and $vm.Guest.IPAddress is space-delimited string
			$vmIPs = $vm.Guest.IPAddress  # casting to Array isn't enough
			#Write-Host ("vmName: $vmName vmIPs: $vmIPs")
			$ipAddress = Choose-IP $vmIPs
			$target = $vmName + "(" + $ipAddress + ")"
			If ( -Not $ipAddress ) { # if no ipAddress we cannot check further
				$target = $vmName + "(" + $vmIPs + ")"
				Write-Logs "FAIL" $target "L2 IP address" "Invalid IP address for L2 $osType machine $vmName. Cannot check. Is this IP address valid?"
				Return # nothing else can be done
			}
			#Write-Host "VerifyDnsNameIP $vmName $ipAddress 'L2'"
			$nameIP = VerifyDnsNameIP $vmName $ipAddress 'L2'
			#Write-Host "get-L2-IP ${nameIP}:$ipAddress"
			Return "${nameIP}:$ipAddress"
		} Else { # have to guess at the name
			Write-Host "No IP address for L2 $osType machine $vmName trying DNS lookup..."
			If ( $vmName -NotLike "*${dom}*" ) { $dnsName = "$vmName.$dom" }
			ElseIf ( $vmName -Like '*_${dom}*' ) { $dnsName = $vmName -Replace '_', '.' } # special treatment for 1903
			Else { $dnsName = $vmName }
			$nameIP = VerifyDnsNameIP  $dnsName "unknown" 'L2'
			If ( $nameIP ) { ($dnsName,$dnsIP) = $nameIP.Split(":")	}
			If ($dnsIP -eq "" ) {
				Write-Logs "WARN" $vmName "L2 DNS" "DNS lookup failed for L2 $osType machine $vmName with no IP address. Please perform $osType checks manually."
				Return # nothing else can be done
			} Else { 
				Return "${nameIP}:$dnsIP"
			}
		}
	}
} # end function get-L2-IP
Export-ModuleMember -Function get-L2-IP

# 8/14/2020 move repetitive L2 snap revert code from main block
Function restorePowerState {
	[CmdletBinding()]
	PARAM (
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$vmName,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$off
	)
	
	BEGIN {
		$vm = Get-VM -Name $vmName
	}
	
	PROCESS {
		#Write-Host "off: $off powerstate: " $vm.PowerState
		If ( ($off -eq $true) -And ( $vm.PowerState -eq "PoweredOn" ) ) {
			Write-Host "Powering off $vmName..."
			$snap = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
			Try {
				$snapError = ''
				$junk = Set-VM -VM $vm -Snapshot $snap -Confirm:$false -ErrorVariable snapError -ErrorAction SilentlyContinue
				If ( $snapError ) {
					Write-Host "Cannot revert snapshot on $vm. $snapError"
				} Else {
					$snaps = Get-Snapshot -VM $vm -Name "autocheck" -ErrorAction SilentlyContinue
					Foreach ( $snap in $snaps ) { 
						Try {
							$junk = Remove-Snapshot -Snapshot $snap -Confirm:$false -ErrorAction SilentlyContinue
						} Catch {
							Write-Host "Cannot remove snapshot $snap."
						}
					}
				}
			} Catch {
				Write-Host "Cannot revert snapshot on $vm. $snapError"
			}
		}
	}
} # end restorePowerState
Export-ModuleMember -Function restorePowerState

Function LogOnTovROPs () {
	[CmdletBinding()]
	PARAM (
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$hostName,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$account
	)
	
	BEGIN {
		$baseUrl = "https://$hostName/suite-api/api"  #Set up the base address
		$url = $baseURL + '/auth/token/acquire'
		$type = "application/json"
		$body=
"{
  ""username"": ""$account"",
  ""password"": ""$password""
}"
	}

	PROCESS {
		[xml]$response = Invoke-WebRequest -Method 'POST' -Uri $url -Body $body -ContentType $type

		$vropsAuthHeaders = @{"Authorization"="vRealizeOpsToken " + $response.'auth-token'.token
"Accept"="application/json"}
	}
	
	END {
		Return $vropsAuthHeaders
	}

}
Export-ModuleMember -Function LogOnTovROPs

Function testsshauthLMC () {
<#
	For use on LMC: This function attempts to establish an ssh session from the LMC to a remote machine with a bogus password. 
	If the date command is successful it returns TRUE else FALSE
#>
	[CmdletBinding()]
	PARAM (
			
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$server,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$userName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$pswrd,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$command
	)
	
	BEGIN {
		$command = $command -Replace '"', "" # no quotes
	}
	
	PROCESS {
		$lcmd = "sshpass -p bogus ssh $username@$server" + ' date && echo "sshauth: TRUE" || echo "sshauth: FALSE"'
		Write-Host $lcmd
		$output = remoteLinuxCmdLMC "mainconsole.$dom" "holuser" $linuxpassword $lcmd
		#Write-Host $LASTEXITCODE
	}
	
	END {
		Return $output
	}
} # End Function testsshauthLMC ()
Export-ModuleMember -Function testsshauthLMC

Function remoteLinuxCmdLMC () {
<#
	For use on LMC: This function creates a temporary ssh shellscript to connect to the $server using $username
	to run $command then runs the script using AutoCheck's expectpass.sh and returns the output.
	If $option is "nsx" then leave out the /bin/sh part of the command.
        $x is for ssh X forwarding (needed for xrandr command on Console)	
#>
	[CmdletBinding()]
	PARAM (
			
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$server,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$userName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$pswrd,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$command,

		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$x
	)
	
	BEGIN {
		$lcmd = "$sshPass -p $pswrd ssh $x $sshOptions ${userName}@$server $command 2>&1"
		#Write-Host $lcmd
	}
	
	PROCESS {
		Try {
			$output = Invoke-Expression -Command $lcmd -ErrorAction SilentlyContinue -ErrorVar errorVar 2>&1
			If ( $output -Like "*denied*" ) { Return "DENIED" } # key added bad password - give up
			If ( $output -Like "*FATAL ERROR*" ) { Return "DENIED" }
		} Catch {
			Write-Host "catch: $errorVar"
			Return $errorVar
		}
	}
	
	END {
		# PowerShell makes it difficult to parse the output if not a String
		$outString = Out-String -InputObject $output -Width 200
		Return $outString
	}
} # End Function remoteLinuxCmdLMC ()
Export-ModuleMember -Function remoteLinuxCmdLMC

# 2024: not using pfSense
# Debian router or pfSense? (Have to put it here because of dependencies.)
<#
$lcmd = "test -f /conf/config.xml;echo `$?"
If ( $isWindows ) {
	Write-Output "TODO: Test for pfSense on Windows"
} ElseIf ( $isLinux ) {
	$isPF = remoteLinuxCmdLMC "router.$dom" $linuxuser $linuxpassword $lcmd
}
#>
$isPF = $False
Export-ModuleMember -Variable isPF

Function scpLMC () {
<#
	scp the file using sshPass
#>
	[CmdletBinding()]
	PARAM (
			
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$source,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$destination,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$pswrd
		
	)
	
	BEGIN { }
	
	PROCESS {
		$lcmd = "$sshPass -p $pswrd scp $sshOptions $source $destination"
		#Write-Host $lcmd
		$output = Invoke-Expression -Command $lcmd
	}
	
	END {
		Return $output
	}
} # End Function scpLMC ()
Export-ModuleMember -Function scpLMC

Function endAutoCheck () {
	#### Copy AutoCheck log and err files ####
	$checkRunFiles = Join-Path -Path $labStartupRoot -ChildPath "AutoCheck.*"
	Copy-Item -Force $checkRunFiles $logDir

	#### Generate the AutoCheckWeb files (only created if no iDisk, i.e., running manually)
	$postprocCSV = Join-Path -Path $PSScriptRoot -ChildPath "postproccsv.ps1"
	Invoke-Expression $postprocCSV
	

	#### Create Zip Archive of all Autocheck output ####
	# This zip file is a convenience for captains to share with their VAT.
	$autocheckZip = Join-Path -Path "/tmp" -ChildPath "autocheck-$vPodName.zip"
	Compress-Archive -Path $logDir -DestinationPath $autocheckZip -Force

	# put just the archive in the $logDir
	$finalZip = Join-Path -Path "/tmp" -ChildPath "autocheck-$vPodName.zip"
	Copy-Item -Force $finalZip $logDir
	
	# copy the HTML files and the zip archive to the mc TEMP folder
	$htmlFile = "autocheck-${vPodName}.html"
	Copy-Item -Force "${logDir}/$htmlFile" $mcTmp
	Copy-Item -Force -Recurse "${logDir}/HTML"  $mcTmp
	Copy-Item -Force $autocheckZip $mcTmp
	# start Firefox to display
	If ( $WMC ) {
		# Unfortunately, Firefox runs in the background when starting remotely. (not visible)
		#$firefoxExe = '"C:\Program Files\Mozilla Firefox\firefox.exe"'
		#$firefoxCmd = "$firefoxExe C:\Temp\$htmlFile"
		#$firefoxCmd | Set-Content ${logDir}/startff.bat
		#Copy-Item -Force ${logDir}/startff.bat $mcTmp
		#$result = RunWinCmd "\Temp\startff.bat" ([REF]$result) 'mainconsole' 'Administrator' $password
		#Write-Host $result
		Write-Output "Open C:\Temp\$htmlFile to view the AutoCheck report."
	} ElseIf ( $LMC ) {
                # due to Firefox snap permissions - copy HTML report /home/holuser
                Copy-Item "/lmchol/tmp/$htmlFile" -Destination "/lmchol/home/holuser/$htmlFile"
		# remove the HTML folder first if it exists (issues with getting updates on multiple runs)
		If (Test-Path -Path "/lmchol/home/holuser/HTML" ) {
			Remove-Item -Path "/lmchol/home/holuser/HTML" -Force -Recurse 
		}
                Copy-Item "/lmchol/tmp/HTML" -Force -Recurse -Destination "/lmchol/home/holuser/HTML"
                # this does not work with Ubuntu 24.04.
		#$lcmd = "/usr/bin/firefox --display=:0 /home/holuser/$htmlFile"
		#Write-Output "Starting Firefox on LMC web console (only) to review AutoCheck report at /tmp/$htmlFile."
		#Write-Output "Exit Firefox when finished."
		Write-Output "Double click the /home/holuser/$htmlFile file on the Console to see the AutoCheck report in Firefox."
		#$output = remoteLinuxCmdLMC "console" "holuser" $linuxpassword $lcmd
		#Write-Host $output
	}

} # End Function endAutoCheck
Export-ModuleMember -Function endAutoCheck

Function checkWindowsScratchDrive () {
	$volumes = Get-Volume | Where-Object {$_.DriveType -eq "Fixed"}
	Foreach ($volume in $volumes) {
		If ( $volume.FileSystemLabel -eq 'System Reserved' ) { Continue }
		If ( $volume.DriveLetter -eq 'C' ) { Continue }
		If ( $volume.FileSystemLabel -eq "IDISK" ) { Continue }  # skip the iDisk
		If ( [byte][char]$volume.DriveLetter -ne 0 ) {
			$dRoot = $volume.DriveLetter + ":\"
			$items = Get-ChildItem -Path $dRoot
			Foreach ( $item in $items ) {
				$p = $dRoot + $item.Name
				$mode = [String]$item.Mode
				$sizeMB = "{0:N2} MB" -f ((Get-ChildItem $p -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
				$dir += $mode + "`t" + $item.Name + "`t" + $sizeMB + "`n"
			}
			$info = "Found additional volume: " + $volume.DriveLetter + ": " + $volume.FileSystemLabel + "`n" + $dir
			Write-Logs "WARN" "Cleanup" "Scratch Drive" $info
		} Else {
			$sizeGB = [math]::Round($volume.Size/1GB,2)
			Write-Logs "WARN" "Cleanup" "Scratch Drive" "Found additional volume with no drive letter and size: $sizeGB"
		}
	}

} # End Function checkWindowsScratchDrive
Export-ModuleMember -Function checkWindowsScratchDrive

Function checkLinuxScratchDrive () {
	$mounts = @("Mounted",
		"/dev",
		"/run",
		"/dev/shm",
		"/run/lock",
		"/sys/fs/cgroup",
		"/snap/",
		"/boot/efi",
		"/run/user/1000",
		"/media/cdrom0",
		"/mnt/idisk/")
	
	If ( $logDir -Like "*idisk*" ) { $dCount = 6
	} Else { $dCount = 4 }

	$drives = Get-ChildItem -Path /dev/sd* -Name
	If ( $drives.Count -gt $dCount ) {
		$output = Invoke-Expression "df -h"
		ForEach ( $line in $output ) {
			#Write-Host $line
			$found = $false
			($dev, $sizeGB, $used, $avail, $use, $mount) = $line -split '\s+' -match '\S'
			If ( $mount -eq '/' ) { Continue }			
			If ( $line -Like "*cdrom0*" ) { Continue }
			If ( $line -Like "*idisk*" ) { Continue }
			ForEach ( $mnt in $mounts ) {
				If ( $mount -Like "*$mnt*") {
					$found = $true
					Break
				}
			}
			If ( -Not $found ) {
				Write-Logs "WARN" "Cleanup" "Scratch Drive" "Found additional volume $mount with size: $sizeGB"
			}
		}
	}
} # End Function checkLinuxScratchDrive
Export-ModuleMember -Function checkLinuxScratchDrive

Function checkSslCert ( [String]$url ) {
	$ExtraCertDetails = $false
	$h = [regex]::Replace($url, "https://([a-z\.0-9\-]+).*", '$1')
		
	If( ($url.Split(':') | Measure-Object).Count -gt 2 ) {
		$p = [regex]::Replace($url, "https://[a-z\.0-9\-]+\:(\d+).*", '$1')
	} Else { $p =	443 }
	#Write-Output $h on port $p

	If( $ExtraCertDetails ) {
		$item = "" | select HostName, PortNum, CertName, Thumbprint, Issuer, EffectiveDate, ExpiryDate, DaysToExpire
	} Else {
		$item = "" | select HostName, PortNum, CertName, ExpiryDate, DaysToExpire, Issuer
	}

	$item.HostName = $h
	$item.PortNum = $p
	Test-TcpPortOpen -Server $h -Port $p -Result ([REF]$result)
	If( $result -eq "success" ) {
		#Get the certificate from the host
		$wr = [Net.WebRequest]::Create("https://$h" + ':' + $p)
		
		#The following request usually fails for one reason or another:
		# untrusted (self-signed) cert or untrusted root CA are most common...
		# we just want the cert info, so it usually doesn't matter
		Try {
			Write-Host "Checking $h" 
			$response = $wr.GetResponse()
			#This sometimes results in an empty certificate... probably due to a redirection
			$success = $true
			If( $wr.ServicePoint.Certificate ) {
				If( $ExtraCertDetails ) {
					$t = $wr.ServicePoint.Certificate.GetCertHashString()
					$SslThumbprint = ([regex]::matches($t, '.{1,2}') | %{$_.value}) -join ':'
					$item.Thumbprint = $SslThumbprint
					$item.EffectiveDate = $wr.ServicePoint.Certificate.GetEffectiveDateString()
				}
				$cn = $wr.ServicePoint.Certificate.GetName()
				$item.CertName = $cn.Replace('CN=',';').Split(';')[-1].Split(',')[0]
				$item.Issuer = $wr.ServicePoint.Certificate.Issuer
				$item.ExpiryDate = $wr.ServicePoint.Certificate.GetExpirationDateString()
				$expiryDate = ($wr.ServicePoint.Certificate.GetExpirationDateString()).Split()
				$validTime = New-Timespan -End $item.ExpiryDate -Start $minValidDate
				If( $validTime.Days -lt 0 ) {
					$output = "expires " + $expiryDate[0] + " " + $validTime.Days + " - *** EXPIRES BEFORE $expirationDate *** "
					Write-Logs "FAIL" $url $function $output
				} Else {
					$output = "expires " + $expiryDate[0] + " " + $validTime.Days + " days past $expirationDate"
					Write-Logs "PASS" $url $function $output
				}
			} Else {
				$output = "Unable to get certificate for $h. Please check manually. $response"
				Write-Output $output
				Write-Logs "FAIL" $url $function $output
			}
		}
		Catch{
			$success = $false
			$output = "Unable to get certificate for $h on $p"
			Write-Logs "FAIL" $url $function $output
		}
		Finally {
		if( $response -And $success ) {
				$response.Close()
				Remove-Variable response
			}
		}
	}
} # End Funstion checkSslCert
Export-ModuleMember -Function checkSslCert
