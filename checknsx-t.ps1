# 30-April 2024

# updated for LMC plink - NOT TESTED

# need this stuff at a minumum

$autocheckModulePath = Join-Path -Path $PSSCriptRoot -ChildPath "autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

<#
# Overwrite logs - useful in development but do not use for production
Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file
Set-Content -Path $csvDetailFile -Value "" -NoNewline # overwrite existing log file
#>

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]
$target = $hostname + "(" + $ipTarget + ")"

# 08/31/2020 adding password checking for root and audit in addition to admin.
$nsxTusers = @( "admin",
		"root",
		"audit" )

If ( $args[2] -eq "nolog" ) {
	$log = $false
} Else {
	$log = $true
}

# $nsxt = $True # no longer needed for LMC remoteLinuxCmdLMC
Write-Logs "WARN" $target "NSX-T checks" "NSX-T checks not tested yet."

Foreach ( $nsxTuser in $nsxTusers ) {
	$pwCmd = "get user $nsxTuser password-expiration"
	If ( $isWindows ) {
		# use hostName instead of ipTarget to avoid plink bug and risk LOCKING the appliance
		$wcmd = "Echo Y | $plinkPath -ssh $hostName -l $nsxuser -pw $nsxpassword $pwCmd  2>&1"
		#Write-Output "$wcmd"
		$output = Invoke-Expression -Command $wcmd -ErrorVariable errorVar
	} ElseIf ( $isLinux ) {
		$output = remoteLinuxCmdLMC $hostName $nsxuser $nsxpassword $pwCmd
	}

	If ( $output -Like "*expires*" ) {
		If ( $log ) { Write-Logs "FAIL" $target "NSX-T password expiration" "NSX-T $nsxTuser $output please clear user $nsxTuser password-expiration" }
	} ElseIf ( $output -Like "Password expiration not configured for this user*" ) {
		If ( $log ) { Write-Logs "PASS" $target "NSX-T password expiration" "NSX-T password for $nsxTuser has no expiration. Thanks!" }
	} ElseIf ( $errorVar ) {
		$errorVar = $errorVar -Replace "`n|" #remove newlines
		If ( $log ) { Write-Logs "FAIL" $target "NSX-T password expiration" "Cannot check NSX-T password for $nsxTuser expiration on $hostName $errorVar" }
	}
}

###############
# 09/03/2020 get the NSX-T license information AFTER checking account password expiration if NOT Edge

If ( $hostName -Like "*edge*" ) { Exit } # Do not check NSX-T licensing on an NSX-T Edge component

<# 
GET /api/v1/licenses
{
  "results" : [ {
    "license_key" : "012CQ-JNJ40-T8KDT-0732H-24V30",
    "is_eval" : false,
    "expiry" : 1640908800000,
    "is_expired" : false,
    "description" : "NSX Data Center Enterprise Plus",
    "quantity" : 12,
    "capacity_type" : "CPU"
  } ],
  "result_count" : 1
}
#>

###############

$sp = [System.Net.ServicePointManager]::SecurityProtocol
#ADD TLS1.2 to the default (SSLv3 and TLSv1)
[System.Net.ServicePointManager]::SecurityProtocol = ( $sp -bor [System.Net.SecurityProtocolType]::Tls12 )
		
#Disable SSL validation (usually a BAD thing... but this is a LAB)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

###############

# need to be told the license expiration date for this vPod
$licenseExpireDate = Get-Date "$expirationDate 12:00:00 AM"
$chkDateMin = $licenseExpireDate.AddDays(-30)
$chkDateMax = $licenseExpireDate.AddDays(30)

$baseUrl = "https://$ipTarget/api"  #Set up the base address
$url = $baseURL + '/session/create'
$body = "j_username=$nsxuser&j_password=$nsxpassword"

Try {
	$response = Invoke-WebRequest -Method 'POST' -Uri $url -Body $body -SessionVariable session -ErrorVar errorVar
	$authToken = $response.Headers["X-XSRF-TOKEN"]
	$nsxTAuthHeader = @{"X-XSRF-TOKEN"=$authToken}
} Catch {
	Write-Output "Cannot login to check NSX-T licensing on $hostName $response $errorVar"
	# should exit at this point
}

Try {		
	$licenseURL = $baseUrl + '/v1/licenses'
	$jsonResponse = Invoke-WebRequest -Method 'GET' -Uri $licenseURL -Headers $nsxTAuthHeader -WebSession $session -ErrorVar errorVar
	$licenseInfo = $jsonResponse | ConvertFrom-Json
	#Write-Host $licenseInfo.results
	Foreach ( $result in $licenseInfo.results ) {
		[int64]$epochExp = $result.expiry
		$expDate = $epoch.AddMilliSeconds($epochExp)
		$licenseDesc = $result.description
		#Write-Output  "expDate: $expDate chkDateMin: $chkDateMin chkDateMax: $chkDateMax"
		If ( $result.is_eval ) {
			Write-Logs "FAIL" $target "NSX-T licensing" "$result.description license on $target is an evaluation. Please use a proper HOL license."
		}
		If( $expDate -and (($expDate -ge $chkDateMin) -and ($expDate -le $chkDateMax)) ) {
			Write-Logs "PASS" $target "NSX-T licensing" "$licenseDesc license on $target is good and expires $expDate"
		} Else {
			If ( $licenseDesc.Contains('vShield Endpoint') ) {				
				Write-Logs "INFO" $target "NSX-T licensing" "$licenseDesc license on $target is bad and never expires but this is normal."
			} Else {
				Write-Logs "FAIL" $target "NSX-T licensing" "$licenseDesc license on $target is bad. Expires on $expDate"
			}
		}
	}
} Catch {
	Write-Output "Cannot check NSX-T licensing on $hostName $jsonResponse $errorVar"
	Write-Logs "FAIL" $target "NSX-T licensing" "Cannot check NSX-T licensing on $hostName $jsonResponse $errorVar"
	Exit
} Finally {
	$logoutURL = $baseUrl + '/session/destroy'
	$jsonResponse = Invoke-WebRequest -Method 'GET' -Uri $logoutURL -Headers $nsxTAuthHeader -WebSession $session -ErrorVar errorVar
}
