# 10-May 2024

# 05/11/2021 set $type = "application/json" for Invoke-WebRequest
# 04/28/2021 LMC NOT IMPLEMENTED (won't be able to test until trusted cert is avaiable on vROPS appliance)

# need this stuff at a minumum

$autocheckModulePath = Join-Path $PSSCriptRoot -ChildPath "autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Host "Abort."
	Exit
}

#$result must be created in order to pass as reference for looping
$result = ''



##############################################################################
##### BEGIN HERE
##############################################################################

# easiest way to avoid the proxy since firewall is open for the Manager.
$ENV:HTTPS_PROXY = ""
$ENV:https_proxy = ""

<#

The vROPs API is documented on the appliance itself:
https://vr-operations.$dom/suite-api/docs/rest/index.html


POST to /api/auth/token/acquire) then do a GET to /api/deployment/licenses

{
  "solutionLicenses" : [ {
    "id" : "928da069-b5db-4312-b073-34869763ef6e",
    "licenseKey" : "R502G-N0Z0J-N8U88-0QPRK-AADER",
    "expirationDate" : 1586010561394,
    "capacity" : " 100 Virtual Machines",
    "usage" : " 120 Virtual Machines",
    "edition" : null,
    "others" : [ ],
    "otherAttributes" : { }
  } ]
} 
#>

###############

$sp = [System.Net.ServicePointManager]::SecurityProtocol
#ADD TLS1.2 to the default (SSLv3 and TLSv1)
[System.Net.ServicePointManager]::SecurityProtocol = ( $sp -bor [System.Net.SecurityProtocolType]::Tls12 )
		
#Disable SSL validation (usually a BAD thing... but this is a LAB)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

###############

$hostName = $args[0]
$ipTarget = $args[1] # IP address will NOT work for REST calls. Trust cannot be established so DNS is a requirement

$target = $hostName + "(" + $ipTarget + ")"

# need to be told the license expiration date for this vPod
$licenseExpireDate = Get-Date "$expirationDate 12:00:00 AM"
$chkDateMin = $licenseExpireDate.AddDays(-30)
$chkDateMax = $licenseExpireDate.AddDays(30)

$baseUrl = "https://$hostName/suite-api/api"  #Set up the base address
$user = "admin" # VROPs administrative account


$authHeaders = LogOnTovROPs $hostName $user

Write-Logs "WARN" $target "Operations Appliance" "Operations appliance checks are NOT TESTED yet."


# retrieve the vROPs JSON license information
Try {
	$type = "application/json"
	$jsonResponse = Invoke-WebRequest -Method 'GET' -Uri "${baseUrl}/deployment/licenses" -Headers $authHeaders -ContentType $type -ErrorAction SilentlyContinue
	$licenseInfo = $jsonResponse | ConvertFrom-Json
	[int64]$epochExp = $licenseInfo.solutionLicenses.expirationDate
	$expDate = $epoch.AddMilliSeconds($epochExp)
	If( $expDate -and (($expDate -ge $chkDateMin) -and ($expDate -le $chkDateMax)) ) {
		Write-Logs "PASS" $target "vROPs licensing" "vRealize Operations license on $target is good and expires $expDate"
	} Else {
		Write-Logs "FAIL" $target "vROPs licensing" "vRealize Operations  license on $target is bad. Expires on $expDate"
	}
} Finally {
	$response = Invoke-WebRequest -Method 'POST' -Uri  "${baseUrl}/auth/token/release" -Headers $authHeaders -ContentType $type -ErrorAction SilentlyContinue
}
