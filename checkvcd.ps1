# 06-June 2025

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

#Change me to shut off the text on the screen
#$global:VCDLibDebug = $false
###############
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
###############

# easiest way to avoid the proxy since firewall is open for the Manager.
$ENV:HTTPS_PROXY = ""
$ENV:https_proxy = ""

$hostName = $args[0]
$ipTarget = $args[1] # IP address will NOT work for REST calls. Trust cannot be established so DNS is a requirement

$target = $hostName + "(" + $ipTarget + ")"

$username = "Administrator" # guessing here. hopefully this is the convention
$orgName = "system"
$baseUrl = "https://$hostName/api"  #Set up the base address


# DEBUG
#$baseUrl = "https://$hostName/api"

# use the highest version number
$url = $baseURL + '/versions'

Write-Output "Checking Cloud Director is NOT TESTED yet."
Write-Logs "WARN" $target "VCD Appliance" "Cloud Director checks are NOT TESTED yet."

Try {
	$ret = Invoke-RestMethod -Method "GET" -Uri $url -Headers @{Accept = "application/*+xml"}  -ErrorVar errorVar #-ContentType $contentType
}
Catch {
	Write-Host "Error: $errorVar"
	Exit 1
}


$versionData = $ret.SelectSingleNode("/*")
$versions = $versionData.VersionInfo
$apiVersion = [String]($versions[$versions.Length-1]).version # select the highest API version listed
#Write-Host "apiVersion: $apiVersion"


# need to be told the license expiration date for this vPod
$licenseExpireDate = Get-Date "$expirationDate 12:00:00 AM"
$chkDateMin = $licenseExpireDate.AddDays(-30)
$chkDateMax = $licenseExpireDate.AddDays(30)

$headers = LogOnToVCD -server $hostName -orgName $orgName -userName $username -password $password -apiVersion $apiVersion
#Write-Host "headers: $headers"
$vCDTokenType = $headers.TokenType
$vCDToken = $headers.Token


Try {
	$licenseData = Get-VCDData -url "https://${hostName}/api/admin/extension/settings/license" -apiVersion $apiVersion -TokenType $vCDTokenType -Token $vCDToken
	$expDate = Get-Date ( $licenseData.ExpirationDate )
	If( $expDate -and (($expDate -ge $chkDateMin) -and ($expDate -le $chkDateMax)) ) {
		Write-Logs "PASS" $target "vCD licensing" "vCloud Director license on $target is good and expires $expDate"
	} Else {
		Write-Logs "FAIL" $target "vCD licensing" "vCloud Director license on $target is bad. Expires on $expDate"
	}
}
Finally {
	LogOffFromVCD -server $hostName -apiVersion $apiVersion -TokenType $vCDTokenType -Token $vCDToken
}
# now check the vApp and vApp Template storage expirations using PowerCLI
# turn off the annoying deprecation warnings
$config = Set-PowerCLIConfiguration -DisplayDeprecationWarnings:$false -Confirm:$false
$vcdConnection = Connect-CIServer $hostName -user $username -password $password -WarningAction silentlyContinue

# make sure storage lease for all vApps and vApp Templates are non-expiring
$civApps = Get-CIVApp
Foreach ($civApp in $ciVapps) {
	$name = $civApp.Name
	$storeLease = $civApp.StorageLease
	If ( $storeLease ) {
		#Write-Output "FAIL vApp Storage Lease for $name expires in $storageLease"
		Write-Logs "FAIL" $hostName "vApp storage lease" "vCloud Director $hostName storage lease on vApp $name is bad and expires in $storeLease."
	} Else {
		#Write-Output "PASS vApp Storage Lease for $name never expires."
		Write-Logs "PASS" $hostName "vApp storage lease" "vCloud Director $hostName storage lease on vApp $name is good and never expires."
	}
}

$civAppTemplates = Get-CIVAppTemplate
Foreach ($civAppTemplate in $civAppTemplates ) {
	$name = $civAppTemplate.Name 
	$storeLease = $civAppTemplate.StorageLease
	If ( $storeLease ) {
		#Write-Output "FAIL vApp Template Storage Lease for $name expires in $storageLease"
		Write-Logs "FAIL" $hostName "vApp Template storage lease" "vCloud Director $hostName storage lease on vApp Template $name is bad and expires in $storeLease."
	} Else {
		#Write-Output "PASS vApp Template Storage Lease for $name never expires."
		Write-Logs "PASS" $hostName "vApp Template storage lease" "vCloud Director $hostName storage lease on vApp Template $name is good and never expires."
	}
}

# anything else?

Try {
	Disconnect-CIServer * -Confirm:$false -WarningAction silentlyContinue
} Catch {}
