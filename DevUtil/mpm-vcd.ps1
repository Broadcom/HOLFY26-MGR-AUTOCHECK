#Change me to shut off the text on the screen
$global:VCDLibDebug = $true
$global:VCDApiVersion = '32.0'
###############
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
###############
function Call-VCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$TokenType=$global:VCDTokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$Token=$global:VCDToken,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		$Url,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RequestType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion=$global:VCDApiVersion,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ContentType='application/*+xml',
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Body,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$InFile
	)
	
	$optionalParams = @{}
	if($Body) {
		$optionalParams["Body"] = $Body
	}
	if($InFile) {
		$optionalParams["InFile"] = $InFile
	}
	
	try {
		Write-Log -WriteToConsole $global:VCDLibDebug -Message "Performing $RequestType to $Url using $TokenType Token (API Version: $ApiVersion)"
		#Write-Host "$RequestType $Url"
		# if($Body) { Write-Host $Body }
		return Invoke-RestMethod -Method $RequestType -Uri $Url -Headers @{Authorization = "$TokenType $Token"; Accept = "application/*+xml;version=$ApiVersion" } -ContentType $ContentType @optionalParams
	}
	catch {
		Write-Log -WriteToConsole $global:VCDLibDebug -Level Error -Message ("Error in performing $RequestType - " + $_.Exception)
		Write-Host $_.Exception.Response.RequestMessage
	}
}
function LogOffFromVCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Server=$global:VCDServer,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$TokenType=$global:VCDTokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$Token=$global:VCDToken,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion=$global:VCDApiVersion
	)
	
	$Url =	"https://$Server/api/session"
	Call-VCD -RequestType "DELETE" -TokenType $TokenType -Token $Token -Url $Url -ApiVersion $ApiVersion | Out-Null
	
	if( (-not ([string]::IsNullOrEmpty($global:VCDServer) ) ) -and ( $global:VCDServer -eq $Server) )	{
		$global:VCDToken = $null
		$global:VCDTokenType = $null
		$global:VCDServer = $null
		$global:VCDQueryUrl = $null
	}
	
}
function LogOnToVCD {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$UserName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$OrgName,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Server,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion=$global:VCDApiVersion
	)
	
	$vcduser = "${UserName}@${OrgName}"
	$baseUrl = "https://$Server/api"
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${vcduser}:${Password}"))
	$auth = "Basic $base64AuthInfo"
	$accept = "application/*;version=$ApiVersion"
	$type = "application/xml"
	$headers = @{ Authorization = $auth; Accept = $accept }
	# $secpass = ConvertTo-SecureString -String $Password -AsPlainText -Force
	# $credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ($UserName + "@" + $OrgName), $secpass
	Write-Log -WriteToConsole $global:VCDLibDebug -Message ("Logging in to $Server as $vcduser")
	try { 
		#-Credential $credential
		$response = Invoke-WebRequest -Method 'POST' -Uri "${baseUrl}/sessions" -Headers $headers -ContentType $type
		# Invoke-RestMethod -Method 'POST' -Uri "${baseUrl}/sessions" -Headers @{Authorization = "Basic $base64AuthInfo"; Accept = "application/*;version=$ApiVersion" } -ContentType  # -ResponseHeadersVariable sessionResponse
		if( (-not ([string]::IsNullOrEmpty($global:VCDServer) ) ) -and ( $global:VCDServer -ne $Server) )	{
			Write-Log -WriteToConsole $global:VCDLibDebug -Level Warn -Message "Connected to multiple servers in a single context! Currently $Server data is stored globally!"
		}
		$global:VCDToken = $response.Headers["X-VMWARE-VCLOUD-ACCESS-TOKEN"]
		$global:VCDTokenType = $response.Headers["X-VMWARE-VCLOUD-TOKEN-TYPE"]
		$global:VCDServer = $Server
		$global:VCDQueryUrl = "https://$Server/api/query"
		if($ApiVersion -ne $global:VCDApiVersion) {
			$global:VCDApiVersion = $ApiVersion
		}
		Write-Log -WriteToConsole $global:VCDLibDebug -Message ("Query URL Set: " + $global:VCDQueryUrl)
		Write-Log -WriteToConsole $global:VCDLibDebug -Message ("Token Type Set: " + $global:VCDTokenType)
	}
	catch {
		Write-Log -WriteToConsole $global:VCDLibDebug -Level Error -Message $($PSItem.ToString())
	}
	Write-Log -WriteToConsole $global:VCDLibDebug -Message "Successfully Connected to $Server"
	
	
	return @{ "TokenType" = $($response.Headers["X-VMWARE-VCLOUD-TOKEN-TYPE"]); "Token" = $($response.Headers["X-VMWARE-VCLOUD-ACCESS-TOKEN"]); }
}
function Write-Log {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true,
			ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias("LogContent")]
		[string]$Message,
		
		[Parameter(Mandatory=$false)]
		[Alias('LogPath')]
		[string]$Path,
		
		[Parameter(Mandatory=$false)]
		[ValidateSet("Error","Warn","Info")]
		[string]$Level="Info",
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$WriteToConsole=$true,
		
		[Parameter(Mandatory=$false)]
		[switch]$NoClobber
	)

	Begin
	{
		# Set VerbosePreference to Continue so that verbose messages are displayed.
		$VerbosePreference = 'Continue'
		# Format Date for our Log File
		$FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
		
		###Basically - if the Path is valid - write to file.
		$WriteToFile =	( -not ([string]::IsNullOrEmpty($Path) ) ) 
	}
	Process
	{
		# Write message to error, warning, or verbose pipeline and specify $LevelText
		switch ($Level) {
			'Error' {
				$cmd = 'Write-Error'
				$LevelText = 'ERROR:'
				#if($WriteToConsole) { Write-Error	"$FormattedDate $LevelText $Message" }
			}
			'Warn' {
				$cmd = 'Write-Warning'
				$LevelText = 'WARNING:'
			}
			'Info' {
				$cmd = 'Write-Host'
				$LevelText = 'INFO:'
			}
		}
		if($WriteToConsole) { Invoke-Expression "$cmd '$FormattedDate $LevelText $Message'" }
		if ( $WriteToFile ) {
			# If the file already exists and NoClobber was specified, do not write to the log.
			if ((Test-Path $Path) -AND $NoClobber) {
				Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
				Return
			}
			# If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
			elseif (!(Test-Path $Path)) {
				Write-Verbose "Creating $Path."
				$NewLogFile = New-Item $Path -Force -ItemType File
			}
			# Write log entry to $Path
			"$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
		}
	}
}
function Get-VCDData {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$TokenType=$global:VCDTokenType,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		$Token=$global:VCDToken,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Url,
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ContentType='application/*+xml',
		
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion=$global:VCDApiVersion
	)
	$ret = Call-VCD -RequestType "GET" -TokenType $TokenType -Token $Token -Url $Url -ApiVersion $ApiVersion -ContentType $ContentType
	if($ret) {
		return $ret.SelectSingleNode("/*")
	} else {
		throw "GET to $Url returned NULL value"
	}
}
$username = "Administrator"
$pass = "VMware1!"
$orgName = "system"
$server = "vcd-01a.corp.local"

$shh = LogOnToVCD -Server $server -OrgName $orgName -UserName $username -Password $pass
try {
	$lic_data = Get-VCDData -Url "https://${server}/api/admin/extension/settings/license"
	Write-Log ("Expiration Date: " + $lic_data.ExpirationDate)
}
finally {
	LogOffFromVCD
}