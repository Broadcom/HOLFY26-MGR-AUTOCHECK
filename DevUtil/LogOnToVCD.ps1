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