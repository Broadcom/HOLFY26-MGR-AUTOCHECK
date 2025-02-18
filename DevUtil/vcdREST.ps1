Bill, here are some functions I had been working on to use REST via PowerCLI against vCD. 
They're not pretty, but they should do the basics and then there are some more complex examples of how I was using it. 

Logging in (using the functions that follow these examples)

##### LOGGING IN
$VCDHOST = 'vcore3-us04.oc.vmware.com'
$VCDORG = 'us04-3-hol-dev-d'
$APIVER = '29.0'
$username = 'my_ussername'
$password = 'my_password'

if( $vcdOrg ) {
  $user = $username + '@' + $vcdOrg 
} else {
  $user = $username + '@system'
}


#Set up the base address
$baseurl = "https://$vcdHost/api"

# Log in -- sometimes, this fails... and just hangs here. Windows ?!?
$vCDConnection = Get-VCDRestAuth -BaseURL $baseurl -user $user -password $password
$authHeader = $vCDConnection.Auth.Headers["x-vcloud-authorization"]

#do "stuff"
(usually have to pass AuthHeader)

#Logging out
Disconnect-VCDRestSession -BaseUrl $baseurl -Auth $authHeader


### use the following


##### VCD REST 

#*===========================================================================
#* Function: Gets Auth String for vCD
#*===========================================================================
Function Get-VCDRestAuth {
<#
                EXAMPLE: 
                                $vCDConnection = Get-VCDRestAuth -BaseURL $baseurl -user $user -password $password
                                $authHeader = $vCDConnection.Auth.Headers["x-vcloud-authorization"]
#>
                [CmdletBinding()] 

                PARAM(
                                $BaseURL = $(throw "-BaseURL is required"), 
                                $User = $(throw "-User is required"), 
                                $Password  = $(throw "-Password is required"), 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {

                                # Create full address of resource to be retrieved
                                $resource = '/versions'
                                $url = $baseurl + $resource
                                # Unauthenticated GET: request and display API versions supported and corresponding service URLs
                                #NOTE: I think passing (undefined?) "headers" was causing the unauthenticated GET to fail on subsequent calls.
                                #$versions = Invoke-RestMethod -Uri $url -Headers $headers -Method 'GET'
                                $versions = Invoke-RestMethod -Uri $url -Method 'GET'
                                ForEach( $ver in $versions.SupportedVersions.VersionInfo ) { Write-Verbose $($ver.Version) }

                                # Get the login URL for the specified APIVER
                                ForEach ($ver in $versions.SupportedVersions.VersionInfo) {
                                                if ( ($ver.Version -eq $ApiVersion) -and ($ver.Deprecated -ne "true") ) { 
                                                                #$headers += @{"Authorization"="Basic $($EncodedPassword)"}
                                                                $loginUrl = $ver.LoginUrl 
                                                }
                                }

                                #$url = $baseURL + "/sessions"
                                if( $loginUrl -ne "" ) {
                                                Write-Host -ForegroundColor Green "Trying to connect to $loginUrl using API version $ApiVersion"
                
                                                $webRequest = [System.Net.WebRequest]::Create( $loginUrl )
                                                $webRequest.ServicePoint.Expect100Continue = $false
                                                $webRequest.PreAuthenticate = $true
                                                $webRequest.Method = "POST"
                                                $webRequest.Accept = "application/*+xml;version=$ApiVersion";
                                                $webRequest.Credentials = New-Object System.Net.NetworkCredential($user,[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))

                                                $resp = $webRequest.GetRequestStream()
                                                $rs = $webRequest.GetResponse()
                                                
                                                #what happens if you get something here... 401?

                                                [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs.GetResponseStream()
                                                [string]$results = $sr.ReadToEnd()
                                
                                                #dispose of the web object... would this do bad things because we're assigning "rs" below?
                                                #Remove-Variable webRequest

                                                Return New-Object PSObject -Property @{Auth=$rs ; HTTP=[xml]$results}

                                } else {
                                                Write-Host -ForegroundColor Red "FAILED trying to connect to $loginUrl using API version $ApiVersion"                      
                                }
                }
}#Get-VCDRestAuth



Function Disconnect-VCDRestSession {
<#
#>
                [CmdletBinding()] 

                PARAM(
                                $BaseUrl = $(throw "-BaseUrl is required"),
                                $Auth = $(throw "-Auth is required"), 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $url = $BaseUrl + '/session'
                                try {
                                                $result = Set-VCDRestDelete -URL $url -Auth $Auth -ApiVersion $ApiVersion
                                }
                                catch {
                                                Write-Host "Something went wrong with logoff ??"
                                }
                }
} #Disconnect-VCDRestSession


#*===========================================================================
#* Script Function: REST GET for vCD
#*===========================================================================
Function Get-VCDRestGet {
<#
                EXAMPLE: 
                                $vappURL = $baseurl +"/query?type=vAppTemplate&filter=(name==*DOUG)"
                                $vappinfo = Get-VCDRestGet -URL $vappURL -auth $authHeader
                                $queryResults = $vappinfo.QueryResultRecords.VAppTemplateRecord
                                $myvAppUrl = $vappinfo.QueryResultRecords.VAppTemplateRecord.href
                                $myvapp = Get-VCDRestGet -URL $myvAppUrl -auth $authHeader
#>
                [CmdletBinding()] 

                PARAM(
                                $URL = $(throw "-URL is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $webRequest = [System.Net.WebRequest]::Create( $URL )
                                $webRequest.ContentType = "text/html"
                                $webRequest.ServicePoint.Expect100Continue = $false
                                $webRequest.Method = "GET"
                                $webRequest.Headers.Add( "x-vcloud-authorization", $Auth )
                                $webRequest.Accept = "application/*+xml;version=$ApiVersion"
                
                                [System.Net.WebResponse]$resp = $webRequest.GetResponse()
                                Write-Verbose "STATUS: $($resp.StatusDescription)"
                                if( $resp.StatusDescription -eq 'OK' ) {
                                                # Example: could return 401 (Unauthorized) if auth token is bad or expired?
                                                $rs = $resp.GetResponseStream()
                
                                                [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs
                                                [string]$results = $sr.ReadToEnd()
                                                return [xml]$results                                        
                                } else {
                                                Write-Host -ForegroundColor Red "`tNon-OK status received on Get-VCDRestGet: $($resp.StatusCode)  $($resp.StatusDescription)"
                                }              
                }
} #Get-VCDRestGet


#*===========================================================================
#* Script Function: REST PUT/POST for vCD
#*===========================================================================
function Set-VCDRestPutPost {
<#
                EXAMPLE:
                                $myvAppUrl = $vappinfo.QueryResultRecords.VAppTemplateRecord.href
                                $xmltemplate = '<vApp:VAppTemplate xmlns:common="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:vApp="http://www.vmware.com/vcloud/v1.5" name="NEW_NAME" type="application/vnd.vmware.vcloud.vAppTemplate+xml"><vApp:Description>NEW_DESCRIPTION</vApp:Description></vApp:VAppTemplate>'
                                $xml = $xmltemplate
                                $xml = $xml -replace "NEW_NAME","Renamed-This-App-Again-DOUG"
                                $xml = $xml -replace "NEW_DESCRIPTION", "My New Description"
                                $result = Set-VCDRestPutPost -URL $myvAppUrl -auth $authHeader -method PUT -contentType "application/vnd.vmware.vcloud.vAppTemplate+xml;version=29.0" -body $xml
                
#>
                [CmdletBinding()] 

                PARAM(
                                $URL = $(throw "-URL is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                [string]$Method = "POST",
                                [string]$ContentType, 
                                [string]$Body, 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $postContent = [byte[]][char[]][string]$body

                                $webRequest = [System.Net.WebRequest]::Create( $URL )
                                $webRequest.ContentType = $contentType
                                $webRequest.ServicePoint.Expect100Continue = $false
                                $webRequest.Method = $method
                                $webRequest.Headers.Add( "x-vcloud-authorization", $auth )
                                $webRequest.Accept = "application/*+xml;version=$ApiVersion"

                                $resp = $webRequest.GetRequestStream()
                                $resp.Write( $postContent, 0, $postContent.length )
                                $rs = $webRequest.GetResponse()

                                [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs.GetResponseStream()
                                [string]$results = $sr.ReadToEnd()
                
                                return [xml]$results
                }
} #Set-VCDRestPutPost


#*===========================================================================
#* Script Function: REST DELETE for vCD
#*===========================================================================
Function Set-VCDRestDelete {
<#
                EXAMPLE: (logging out)
                                $result = Set-VCDRestDelete -URL $($baseurl + '/session') -auth $authHeader
#>
                [CmdletBinding()] 

                PARAM(
                                $URL = $(throw "-URL is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                [string]$ContentType, 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $webRequest = [System.Net.WebRequest]::Create( $URL )
                                if( $ContentType.length -gt 0 ) {
                                                $webRequest.ContentType = $ContentType
                                }
                                $webRequest.ServicePoint.Expect100Continue = $false
                                $webRequest.Method = "DELETE"
                                $webRequest.Headers.Add( "x-vcloud-authorization", $Auth )
                                $webRequest.Accept = "application/*+xml;version=$ApiVersion"
                
                                [System.Net.WebResponse]$resp = $webRequest.GetResponse()
                                $rs = $resp.GetResponseStream();
                
                                [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs
                                [string]$results = $sr.ReadToEnd()

                                #dispose
                                Remove-Variable webRequest    

                                return [xml]$results
                }
} #Set-VCDRestDelete


################################

#Building on the primitives

                
#*===========================================================================
#* Script Function: retrieve an Org's inventory objects: catalog, vdc, orgNetwork
#*===========================================================================
Function Get-VCDRestOrgInventory {
<#
                Returns a hash table containing the requested resource types
                
                "FilterOvdcs" will remove disabled and "GC" orgvdcs; enabled by default
                
                EXAMPLE: 
                                $ovdc = Get-VCDRestOrgInventory -BaseURL $baseurl -ResourceType 'vdc' -OrgName 'nl01-3-vmworld-hol-u' -Auth $authHeader 
#>
                [CmdletBinding()] 
                
                PARAM(
                                $BaseURL = $(throw "-BaseURL is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $OrgName = $(throw "-OrgName is required"), 
                                [string]$ResourceType, 
                                [Switch]$FilterOvdcs=$true,
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                try {
                                                $url = $BaseURL + '/org'
                                                $response = Get-VCDRestGet -URL $url -Auth $Auth
                                                #TODO: filter based on passed-in $OrgName
                                                Write-Verbose "Visible Orgs:"
                                                foreach( $org in $response.OrgList.org ) { 
                                                                Write-Verbose "`t$($org.name)"
                                                                if( $org.Name -eq $OrgName ) { 
                                                                                $refOrg = $response.OrgList.org.href
                                                                }
                                                }
                                                if( $refOrg -ne $null ) {
                                                                $theOrg = Get-VCDRestGet -URL $refOrg -auth $authHeader
                                                } else {
                                                                Write-Host -ForegroundColor Red "ERROR: unable to find Org $OrgName"
                                                                return $null
                                                }
                                }
                                catch {
                                                Write-Error "UNHANDLED: issue retrieving org $OrgName"
                                                Return $null
                                }
                
                                switch( $ResourceType ) {
                                                "vdc" {
                                                                $orgVdcs = @{}
                                                                foreach( $vdc in $theOrg.Org.Link | where { ($_.rel -eq "down") -and ($_.Type -eq "application/vnd.vmware.vcloud.vdc+xml") } ) { 
                                                                                if( $FilterOvdcs ) {
                                                                                                if( $vdc.name -notmatch "GC" ) { 
                                                                                                                $t = Get-VCDRestGet -URL $vdc.href -Auth $Auth
                                                                                                                if( $t.Vdc.IsEnabled -eq "true" ) {
                                                                                                                                $orgVdcs.Add($vdc.name,$vdc.href) 
                                                                                                                } else {
                                                                                                                                Write-Verbose "`tFiltered out disabled ovdc: $($vdc.name)"
                                                                                                                }
                                                                                                } else {
                                                                                                                Write-Verbose "`tFiltered out 'GC' ovdc: $($vdc.name)"
                                                                                                }
                                                                                } else {
                                                                                                $orgVdcs.Add($vdc.name,$vdc.href)
                                                                                }
                                                                }
                                                                Write-Verbose "`tRead Orgvdcs"
                                                                return $orgVdcs
                                                }
                                                "catalog" {
                                                                $catalogs = @{}
                                                                foreach( $catalog in $theOrg.Org.Link | where { ($_.rel -eq "down") -and ($_.Type -eq "application/vnd.vmware.vcloud.catalog+xml") } ) { 
                                                                                $catalogs.Add($catalog.name,$catalog.href)
                                                                }
                                                                Write-Verbose "`tRead catalogs"
                                                                return $catalogs
                                                }
                                                "orgNetwork" {
                                                                $orgNetworks = @{}
                                                                foreach( $orgNetwork in $theOrg.Org.Link | where { ($_.rel -eq "down") -and ($_.Type -eq "application/vnd.vmware.vcloud.orgNetwork+xml") } ) { 
                                                                                $orgNetworks.Add($orgNetwork.name,$orgNetwork.href)
                                                                }
                                                                Write-Verbose "`tRead Org networks"
                                                                return $orgNetworks
                                                }
                                                default {
                                                                Write-Verbose "UNKNOWN type $ResourceType should be one of 'vdc,'catalog','orgNetwork'"
                                                                return $null
                                                }
                                }
                }
}#Get-VCDRestOrgInventory


#*===========================================================================
#* Script Function: by name, retrieve an object of specified type: 'vApp' and 'vAppTemplate'
#*===========================================================================
Function Get-VCDRestObject {
<#
                EXAMPLE:
                                Get-VCDRestObject -Name $Name -Type 'VAppTemplate' -Auth $authHeader -BaseURL $baseURL
                                
                Returns the href of the object or $null
#>
                [CmdletBinding()] 
                
                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $BaseURL = $(throw "-BaseURL is required"),
                                $Type = "vApp", 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $objectURL = $BaseURL + "/query?type=$Type&filter=(name==$Name)"
                                $objectinfo = Get-VCDRestGet -URL $objectURL -Auth $Auth
                                $queryResults = $objectinfo.QueryResultRecords
                                Write-Verbose "`tMatches found: $($queryResults.total)"

                                #TODO: handle multiple objects (pattern passed instead of explicit name?)
                                if( $queryResults.total -eq 1 ) { 
                                                return $queryResults.($type+"Record").href
                                }
                                elseif( $queryResults.total -gt 1 ) { 
                                                $results = @()
                                                foreach( $qr in $queryResults.($type+"Record") ) {
                                                                $results += $qr.href
                                                }
                                                return $results
                                } else {
                                                return $null
                                }
                }
} #Get-VCDRestObject


#*===========================================================================
#* Script Function: test that a vApp template exists in the org
#*===========================================================================
Function Test-VPodExists {
<#
                EXAMPLE:
                                Test-VPodExists -Name $vpodName -auth $authHeader
                
                TODO: should take a catalog name (with default) and limit search there
#>
                [CmdletBinding()] 
                
                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $BaseURL = $(throw "-BaseURL is required"),
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                Write-Verbose "Starting Test-VPodExists - looking for $Name"
                                if( Get-VCDRestObject -Type "vAppTemplate" -Name $Name -Auth $Auth -BaseURL $BaseURL ) {
                                                Write-Verbose "`tFound $Name"
                                                return $true
                                } else { 
                                                Write-Verbose "`tDid not find $Name"
                                                return $false
                                }
                }
} #Test-VPodExists


#*===========================================================================
#* Script Function: test that a vApp template exists in the org
#*===========================================================================
Function Test-VAppExists {
<#
                EXAMPLE:
                                Test-VAppExists -Name $vappName -Auth $authHeader
#>
                [CmdletBinding()] 
                
                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $BaseURL = $(throw "-BaseURL is required"),
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                if( Get-VCDRestObject -Type "vApp" -Name $Name -Auth $Auth -BaseURL $BaseURL ) {
                                                return $true
                                } else { 
                                                return $false
                                }
                }
} #Test-VAppExists




#*===========================================================================
#* Script Function: return the status of a vApp
#*===========================================================================
Function Get-VAppStatus {
<#
                EXAMPLE:
                                Get-VAppStatus -Name $vappName -auth $authHeader
#>
                [CmdletBinding()] 
                
                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $BaseURL = $(throw "-BaseURL is required"), 
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                $refVApp = Get-VCDRestObject -Type "vApp" -Name $Name -Auth $Auth -BaseURL $BaseURL
                                if( $refVApp -ne $null ) {
                                                $result = $null
                                                $vApp = (Get-VCDRestGet -URL $refVApp -Auth $Auth).VApp
                                                if( $vApp.status -eq 8 ) {
                                                                #8 is "good"
                                                                $result = 'READY'
                                                } elseif ( $vApp.status -eq 0 ) {
                                                                #0 is 'running'
                                                                $task = $vApp.Tasks.Task
                                                                $result = "RUNNING: $($task.Progress) `%"
                                
                                                } else {
                                                                $result = $vApp.status
                                                }
                                                return $result
                                } else { 
                                                Write-Host "`tvApp with name $vAppName was not found."
                                                return $null
                                }
                }              
} #Get-VAppStatus



#*===========================================================================
#* Script Function: Create shadow vApps/VMs for specified template
#*===========================================================================
Function Get-VAppTemplateRef {
<#
                Get the href for a vApp Template, based on name and catalog name
                
                EXAMPLE:
                                $refTemplate = Get-VAppTemplateRef -Name HOL-iSIM-v1.3 -catalogName HOL-Masters -Auth $authHeader

#>
                [CmdletBinding()] 

                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $CatalogName = $(throw "-CatalogName is required"), 
                                $BaseURL = $(throw "-BaseURL is required"),
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                ## TODO: make this BETTER generic ... needs to take OrgName as a parameter instead of hard-coded!
                                #$OrgName = 'nl01-3-vmworld-hol-u'
                                $OrgName = (Get-CloudInfoFromKey -Key $cloudKey)[1]
                                $catalogs = Get-VCDRestOrgInventory -BaseURL $BaseURL -ResourceType 'catalog' -Auth $Auth -OrgName $OrgName

                                ## Enumerate the items in the specified catalog and stuff name, href into a hashtable
                                try {
                                                $theCatalog = Get-VCDRestGet -URL $catalogs[$catalogName] -Auth $Auth
                                                $catalogItems = @{}
                                                foreach( $item in $theCatalog.Catalog.CatalogItems.CatalogItem | where { ($_.NodeType -eq "Element") -and ($_.Type -eq "application/vnd.vmware.vcloud.catalogItem+xml") } ) { 
                                                                $catalogItems.Add($item.name,$item.href)
                                                }
                                                Write-Verbose "`tRead $catalogName catalog - contains $($catalogItems.count) items."

                                }
                                catch {
                                                #TODO: what happens if the catalog we want is not there
                                                Write-Error "UNHANDLED: catalog $catalogName not found"
                                                Return $null       
                                }
                
                                try { 
                                                $t = Get-VCDRestGet -URL $catalogItems[$Name] -Auth $Auth -ApiVersion $ApiVersion
                                                $refTemplate = $t.CatalogItem.Entity.href
                                                Write-Verbose "`tFound the template"
                                }
                                catch {
                                                #TODO: what happens if the template we want is not there
                                                Write-Error "UNHANDLED: template with name $vAppName not found in $catalogName"
                                                Return $null
                                }

                                return $refTemplate
                }
} #Get-VAppTemplateRef



#*===========================================================================
#* Script Function: Create shadow vApps/VMs for specified template
#*===========================================================================
Function Add-VCDRestShadow {
<#
                Assumes user has already logged in and retrieved an authentication token
                We pre-filter the orgvdcs
                
                EXAMPLE:
                                $refTemplate = Get-VAppTemplateRef -Name 'HOL-iSIM-v1.3' -catalogName 'HOL-Masters' -Auth $authHeader
                                $refOrgVdcs = Get-VCDRestOrgInventory -BaseURL $baseurl -ResourceType 'vdc' -Auth $Auth -OrgName 'nl01-3-vmworld-hol-u' -FilterOvdcs
                                Add-VcdRestShadow -refTemplate $refTemplate -OrgVdc $refOrgVdcs 
                
                NOTES: 
                                -Wait will wait for all shadows to complete (or fail?) before moving on.
                                -SleepTime is the delay, in seconds, between checks of the progress
                                
                                -Template takes a CatalogItem (resolving that is {CatalogItem}.Entity.href)
#>

                [CmdletBinding()] 

                PARAM(
                                $Template = $(throw "-Template is required (href)"), 
                                $Auth = $(throw "-Auth is required"), 
                                $OrgVdcs = $(throw "-OrgVdcs is required (Hashtable)"), 
                                $BaseURL = $(throw "-BaseURL is required"), 
                                $SleepTime = 60,
                                [Switch]$Wait,
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                #this is the Content-Type used for deployments
                                $contentType = 'application/vnd.vmware.vcloud.instantiateVAppTemplateParams+xml; charset=ISO-8859-1'

#this is a basic deployment template for HOL
$xml = @'
<?xml version="1.0" encoding="UTF-8"?>
<InstantiateVAppTemplateParams
   xmlns="http://www.vmware.com/vcloud/v1.5"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
   xmlns:vcloud="http://www.vmware.com/vcloud/v1.5"
   name="VAPP_NAME"
   deploy="false"
   powerOn="false">
   <Description>VAPP_DESCRIPTION</Description>
   <InstantiationParams>
      <NetworkConfigSection>
         <ovf:Info>Configuration parameters for logical networks</ovf:Info>
         <NetworkConfig networkName="VAPP_NETWORK_NAME">
           <vcloud:Configuration>
                <vcloud:BackwardCompatibilityMode>true</vcloud:BackwardCompatibilityMode>
                <vcloud:IpScopes>
                    <vcloud:IpScope>
                        <vcloud:IsInherited>false</vcloud:IsInherited>
                        <vcloud:Gateway>192.168.0.1</vcloud:Gateway>
                        <vcloud:Netmask>255.255.255.0</vcloud:Netmask>
                        <vcloud:Dns1>192.168.110.10</vcloud:Dns1>
                        <vcloud:DnsSuffix>corp.local</vcloud:DnsSuffix>
                        <vcloud:IsEnabled>true</vcloud:IsEnabled>
                        <vcloud:IpRanges>
                            <vcloud:IpRange>
                                <vcloud:StartAddress>192.168.0.201</vcloud:StartAddress>
                                <vcloud:EndAddress>192.168.0.220</vcloud:EndAddress>
                            </vcloud:IpRange>
                        </vcloud:IpRanges>
                    </vcloud:IpScope>
                </vcloud:IpScopes>
                <vcloud:FenceMode>isolated</vcloud:FenceMode>
                <vcloud:RetainNetInfoAcrossDeployments>false</vcloud:RetainNetInfoAcrossDeployments>
              </vcloud:Configuration>
            </NetworkConfig>
      </NetworkConfigSection>
   </InstantiationParams>
   <Source
      href="SOURCE_TEMPLATE" />
</InstantiateVAppTemplateParams>
'@

                                #Get the resources (special case to use all orgvdcs)
                                if( $OrgVdcs.GetType().Name -ne "Hashtable" ){
                                                #no orgvdcs?
                                                Write-Error "No OrgVdc hashtable passed in!"
                                                #TODO: support a single record (href?) fr an ovdc to allow a single shadow?
                                                Return $false
                                }

                                #This is needed unless we're wiring up the pods -- which is typically unnecessary for shadows
                                #$orgNetworks = Get-VCDRestOrgInventory -BaseURL $baseurl -ResourceType 'orgNetwork' -Auth $Auth -OrgName 'nl01-3-vmworld-hol-u'

                                #Get some information about the template
                
                                try {
                                                if( $Template -match "catalogItem" ) {
                                                                Write-Verbose "Handling a CatalogItem"
                                                                Write-Verbose "$Template"
                                                                $catalogItem = (Get-VCDRestGet -URL $Template -Auth $Auth -ApiVersion $ApiVersion).CatalogItem
                                                                $refVAppTemplate = $catalogItem.Entity.href
                                                                Write-Verbose "$refVAppTemplate"
                                                } elseif( $Template -match "vAppTemplate" ) {
                                                                $refVAppTemplate = $Template                                
                                                } else {
                                                                Write-Host -ForegroundColor Red "Invalid template passed."
                                                                $refVAppTemplate = $null
                                                                return $false
                                                }
                                                
                                                Write-Verbose "Getting the vApp Template"
                                                $vAppTemplate = (Get-VCDRestGet -URL $refVAppTemplate -Auth $Auth -ApiVersion $ApiVersion).VAppTemplate
                                                $vAppTemplateName = $vAppTemplate.Name
                                                Write-Host -ForegroundColor Green "$(Get-Date) Begin requesting shadows for $vAppTemplateName"

                                                #retreive the vApp's network name from the vApp. There should only be ONE (and the special "none")
                                                $theAppNetworkName = $vAppTemplate.NetworkConfigSection.NetworkConfig[0].networkName

                                                if( $theAppNetworkName.length -eq 0) {
                                                                Write-Verbose "failed first NetworkName check, trying option 2"
                                                                ##SPECIAL CASE
                                                                #I have only seen this in HOL-1981 where someone totally messed up their networking and seem to have deleted the "none"
                                                                $theAppNetworkName = $vAppTemplate.NetworkConfigSection.NetworkConfig.networkName
                                                }
                                                if( $theAppNetworkName.length -eq 0) {
                                                                #still messed up, FAIL
                                                                Write-Host -ForegroundColor Red "ERROR: unable to read vApp network name from $vAppTemplateName"
                                                                Write-Host -ForegroundColor Red "NetworkConfig looks like this:"
                                                                Write-Host "$($vAppTemplate.NetworkConfigSection.NetworkConfig)"
                                                                return $false
                                                
                                                } else {
                                                                Write-Verbose "`tRead vApp network from vApp: $theAppNetworkName"
                                                }
                                } catch {
                                                Write-Error "UNHANDLED: failure while reading vApp network name from $vAppTemplateName template"
                                                return $false
                                }
                
                                #Begin vApp creation requests with each of the orgvdcs in the list
                
                                $refTaskList = @()
                                foreach( $orgVdcName in ($orgvdcs.keys | Sort-Object) ) {
                                                $shadowVappName = $vAppTemplateName + "_shadow_" + $orgVdcName

                                                #need a valid Auth token!

                                                if( -not (Test-VAppExists -Name $shadowVappName -Auth $Auth -BaseURL $baseURL -ApiVersion $ApiVersion) ) {          
                                                                Write-Verbose "Deploying $vAppTemplateName to $orgVdcName as $shadowVappName"
                                                                $deployUrl = $orgvdcs[$orgVdcName] + "/action/instantiateVAppTemplate"
                                                                Write-Verbose "`tdeployment URL:$deployURL"

                                                                #modify the template for this deployment
                                                                $requestBody = $xml -replace "VAPP_NAME",$shadowvAppName
                                                                $requestBody = $requestBody -replace "VAPP_DESCRIPTION","Pre-shadowing on $(Get-Date)"
                                                                $requestBody = $requestBody -replace "SOURCE_TEMPLATE",$refVAppTemplate
                                                                $requestBody = $requestBody -replace "VAPP_NETWORK_NAME",$theAppNetworkName
                                                                # SUPER Verbose              
                                                                #Write-Verbose "=== BODY ==="
                                                                #Write-Verbose $requestBody
                                                                #Write-Verbose "=== BODY ==="

                                                                #GO!
                                                                $shadowvApp = Set-VCDRestPutPost -URL $deployUrl -Auth $Auth -Method 'POST' -contentType $contentType -body $requestBody -ApiVersion $ApiVersion
                                                                #TODO: monitor the spawn tasks somehow in a way that makes sense
                                                                # if the creation fails for some reason, stop... '500 Internal Server Error' is bad
                                                                Write-Verbose "Task spawned: $($shadowvApp.VApp.Tasks.Task.href)"
                                                                $refTaskList += $shadowvApp.VApp.Tasks.Task.href
                                                
                                                } else {
                                                                #vApp exists, we didn't try to create it
                                                                Write-Host -ForegroundColor Yellow "$shadowVappName already exists in $orgVdcName"
                                                }
                                } #foreach orgvdc
                                
                                Write-Host -ForegroundColor Green "$(Get-Date) Finished requesting shadows for $vAppTemplateName"

                                #(optional) monitor them for completion (success of error)... or failure (??)
                                if( $Wait ) {
                                                Write-Host -ForegroundColor Green "$(Get-Date) Monitoring for completion (refresh every $SleepTime seconds):"
                                                $errorCount = 0
                                                $errorVAppNames = @()
                                                $successVAppNames = @()
                                                $numShadowVapps = $refTaskList.Count

                                                while( ($finishedCount -lt $numShadowVapps) -and ($numShadowVapps -ne 0)) {
                                                                $finishedCount = 0
                                                                foreach( $refTask in $refTaskList ) {
                                                                                # KNOWN STATES: 'queued','running' ... 'error'
                                                                                $t = (Get-VCDRestGet -URL $refTask -Auth $Auth).Task
                                                                                Write-Verbose "`t$($t.operation)"
                                                                                #NOTE: operation looks like this:
                                                                                #"Created Virtual Application HOL-1901-v0.15_shadow_us12-c1-VMworld-HOL-UT-PayG-ovDC6(ddf2e864-b5fb-4ec0-adb4-4d70b351c8b9)"
                                                                                $vAppName = ($t.operation) -replace 'Created Virtual Application (.*)\(.*$','$1'
                                                                                Write-Verbose "`tStatus is `'$($t.status)`' at $($t.progress)`% for $vAppName"
                                                                                if( $t.status -eq 'success' ) { 
                                                                                                $finishedCount+=1
                                                                                                $successVAppNames += $vAppName
                                                                                                #TODO: Make this a hashtable or find some way to only put a pod's name in this list ONCE!
                                                                                }
                                                                                # what happens if it fails?? 
                                                                                if( $t.status -eq 'error' ) { 
                                                                                                $errorCount+=1
                                                                                                $errorVAppNames += $vAppName           
                                                                                                $finishedCount+=1
                                                                                }
                                                                                #what does that look like ?
                                                                }
                                                                Write-Host "$vAppTemplateName : Finished $finishedCount of $numShadowVapps"
                                                                if( $finishedCount -ne $numShadowVapps ) { Start-Sleep -Seconds $SleepTime }
                                                } #while not finished
                                                
                                                Write-Verbose "SUCCESS: $successVAppNames"
                                                Write-Verbose "FAIL: $errorVAppNames"
                                                
                                                if( $errorCount -eq 0 ) {
                                                                Write-Host -ForegroundColor Green "$(Get-Date) Finished creating shadows for $vAppTemplateName"
                                                                #delete each successfully deployed vApp
                                                                Write-Host -ForegroundColor Green "Removing shadow vApps for $vAppTemplateName"
                                                                
                                                                foreach( $n in $successVAppNames ) {
                                                                                try {
                                                                                                $d = Delete-VCDRestVApp -Name $n -Auth $Auth -BaseUrl $BaseUrl -ApiVersion $ApiVersion -MaxDelete 2
                                                                                }
                                                                                catch {
                                                                                                Write-Host "`tsomething went wrong trying to delete $n"
                                                                                }
                                                                }
                                                                return $true
                                                } else {
                                                                Write-Host -ForegroundColor Black -BackgroundColor Magenta "$(Get-Date) Errors encountered creating shadows for $vAppTemplateName"
                                                                #leave the "bodies" behind for analysis
                                                                return $false                                      
                                                }

                                } else {
                                                return $true
                                }
                }
} #Add-VcdRestShadow



Function Delete-VCDRestVApp {
<#
                remove a vApp (or more!)
                TODO: should we make sure it is powered off and cleaned up first?
                
                EXAMPLE:
                                Delete-VCDRestVApp -Name 
#>
                [CmdletBinding()] 

                PARAM(
                                $Name = $(throw "-Name is required"), 
                                $Auth = $(throw "-Auth is required"), 
                                $BaseURL = $(throw "-BaseURL is required"), 
                                [Switch]$WhatIf,
                                [Switch]$Force,
                                [int]$MaxDelete=25,
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                
                                $refVApps = Get-VCDRestObject -Name $Name -Auth $Auth -BaseURL $BaseURL -Type "vApp" -ApiVersion $ApiVersion

                                if( $refVApps.Count -eq 0 ) {
                                                Write-Host "Unable to locate vApp $Name"
                                                return $null
                                }

                                $results = @()

                                if( ($refVApps.Count -gt $MaxDelete) -and (-Not $Force) ) {
                                                Write-Host -ForegroundColor Yellow "Cowardly refusing to remove > $MaxDelete vApps at once. $($refVApps.Count) found!"
                                                return $null
                                }
                                
                                foreach( $refVApp in $refVApps ) {
                                                $vApp = (Get-VCDRestGet -URL $refVApp -Auth $Auth).VApp
                                                $refNukeIt = ($vApp.Link | where { $_.rel -eq "remove" }).href
                                                Write-Verbose "Delete-VCDRestVApp - delete link: $refNukeIt"
                                                if( -Not $WhatIf ) {
                                                                if( ($Force) -and ($refVApps.Count -gt $MaxDelete) ) {
                                                                                Write-Host -BackgroundColor Magenta -ForegroundColor White "Force specified, removing $($refVApps.Count) vApps."
                                                                                Write-Host "Multi-page delete (>25) not implemented yet. May need to call again to get the rest."
                                                                                #TODO
                                                                                #We get them in "pages" of 25 from Get-VCDRestObject... need to figure out how to handle those
                                                                                # can call self until (return value).count -eq 0
                                                                }
                                                                
                                                                $results += (Set-VCDRestDelete -URL $refNukeIt -Auth $Auth -ContentType "" -ApiVersion $ApiVersion).Task
                                                                
                                                } else {
                                                                Write-Host "WHATIF:`t deleted $($vApp.Name)"
                                                                $results = $null
                                                }
                                }
                                return $results  
                }
} #Delete-VCDRestVapp


Function Show-CloudPopulationRest {
<#
                Show the vapp template population of each cloud in the specified set
                Uses Show-VpodVersions
                Takes configuration from XML file
                Always calls Show-VpodVersions with the "UseCloudCatalogDefaultCatalogs" option
                                $CatalogName option currently does nothing
#>
                [CmdletBinding()]

                PARAM (
                                $CloudSet = '',
                                $CatalogName = '',
                                $LibPath = 'E:\VMWORLD',
                                $VpodFilter = 'HOL-*',
                                [Switch]$ValidateTemplates
                )
                
                BEGIN {
                                Write-Verbose "$(Get-Date) Beginning Show-CloudPopulationRest for $CLOUDSET"

                                $possibleCloudSets = $knownCloudSets.Keys
                                if( $CloudSet -eq '' ) {
                                                #display a list of known sets
                                                Write-Host "Please provide the name of a known cloud set using the -CoudSet parameter."
                                                Write-Host "Known CloudSets:"
                                                $knownCloudSets.Keys | % { Write-Host "`t$_" }
                                                return
                                }

                                #Make sure the provided set is known
                                if( $knownCloudSets.ContainsKey($CloudSet) ) {
                                                #TODO: do we prefer the catalog from this file or what is passed into this function?
                                                #$theCatalogName = $cloudSetCatalogs[$CloudSet]
                                                $theClouds = $knownCloudSets[$CloudSet]
                                                Write-Host "Checking $CloudSet clouds"
                                }
                                else {     
                                                Write-Host -ForegroundColor Red "Unrecognized cloud set, $cloudSet"
                                                Write-Host "Use one of: "
                                                $knownCloudSets.Keys | % { Write-Host "`t$_" }
                                                return
                                }

                                if( $theClouds.count -gt 0 ) {

                                                if( $theClouds.count -gt 8 ) {
                                                                #Powershell v4 won't display more than 8 columns with Format-Table
                                                                #PowerShell v5+ seems to limit only based on console width
                                                                #FUTURE: split into multiple arrays and run multiple sets?
                                                                #Write-Host -ForegroundColor Yellow "WARNING - Format-Table supports a maximum of 8 columns"
                                                }

                                                $APIVER = '29.0'
                                                $authHeaders = @{}
                                                $connectedClouds = @()
                                                $failedClouds = @()
                                                foreach( $cloud in $theClouds ) { 
                                                                $cloudInfo = Get-CloudInfoFromKey -key $cloud
                                                                $vcdHost = $cloudInfo[0]
                                                                $vcdOrg = $cloudInfo[1]
                                                                $vcdCatalogName = $cloudInfo[2]
                                                                if( $CatalogName -ne '' ) { $vcdCatalogName = $CatalogName }
                                                                $username = 'catalog' #currently, assume all clouds use "catalog" user!

                                                                $cred = New-Object System.Management.Automation.PsCredential $username , $(Get-Content $("E:\Scripts\Credentials\$cloud" + '_credential') | ConvertTo-SecureString)
                                                                $password = $cred.Password

                                                                if( $vcdOrg ) {
                                                                  $user = $username + '@' + $vcdOrg 
                                                                } else {
                                                                  $user = $username + '@system'
                                                                }

                                                                $baseurl = "https://$vcdHost/api"

                                                                Write-Host "connecting to CloudKey $cloud with $baseurl and $user"

                                                                #connecting to multiple clouds using REST
                                                                $vCDConnection = Get-VCDRestAuth -BaseURL $baseurl -user $user -password $password -ApiVersion $APIVER
                                                                #store the auth header for this cloud in a hash table by cloudKey name
                                                                if( $vCDConnection.Auth -ne $null ) {
                                                                                $authHeaders.Add($cloud, $vCDConnection.Auth.Headers["x-vcloud-authorization"])
                                                                                $connectedClouds += $cloud
                                                                } else {
                                                                                Write-Host -ForegroundColor Yellow "*** WARNING: Unable to connect to $cloud ***"
                                                                                $failedClouds += $cloud
                                                                }
                                                                
                                                }
                                                
                                                if( $ValidateTemplates ) {
                                                                Show-VpodVersionsRest -Clouds $connectedClouds -AuthHeaders $authHeaders -Catalog $vcdCatalogName -LibPath $LibPath -VpodFilter $VpodFilter -ValidateTemplates -UseCloudCatalogDefaultCatalogs
                                                }
                                                else {
                                                                Show-VpodVersionsRest -Clouds $connectedClouds -AuthHeaders $authHeaders -Catalog $vcdCatalogName -LibPath $LibPath -VpodFilter $VpodFilter -UseCloudCatalogDefaultCatalogs
                                                }

                                                foreach( $cloud in $authHeaders.Keys ) {
                                                                $cloudBaseUrl = 'https://' + $((Get-CloudInfoFromKey -Key $cloud)[0]) + '/api'
                                                                Write-Verbose "DISCONNECTING from CloudKey $cloud with $cloudBaseUrl and $($authHeaders[$cloud])"
                                                                try { 
                                                                                Disconnect-VCDRestSession -BaseUrl $cloudBaseurl -Auth $authHeaders[$cloud]
                                                                } catch {
                                                                                Write-Host -ForegroundColor Yellow "***Unable to disconnect from $cloudBaseUrl using $($authHeaders[$cloud])"
                                                                }
                                                }
                                }
                                if( $failedClouds.count -gt 0 ) {
                                                foreach( $c in $failedClouds ) { 
                                                                Write-Host -ForegroundColor Yellow "*** INCOMPLETE DATA: Unable to connect to $c"
                                                }
                                }
                }
} #Show-CloudPopulationRest



Function Show-VpodVersionsRest {
<#
                Query Clouds and return presence + version(s) of each one matching VpodFilter
                Assumes $LibPath is authoritative regarding which SKUs should be reported.

                *** Must be authenticated to all $Clouds prior to running this function
                *** uses REST API, so requires a hashtable of authHeaders
#>
                [CmdletBinding()]

                PARAM (
                                $Clouds = $(throw "need -Clouds (array of cloudKeys to search)"),
                                $AuthHeaders = $(throw "need -AuthHeaders (hashtable of authHeaders of connected clouds)"),
                                $CatalogName = '',
                                $LibPath = $DEFAULT_LOCALLIB,
                                $VpodFilter = '*',
                                [Switch]$ValidateTemplates,
                                [Switch]$UseCloudCatalogDefaultCatalogs
                )
                BEGIN {
                                #Setup variables to collect the data
                                $report = @{}
                                $cloudHash = @{}
                                $currentVersions = @{}
                                $Clouds | % { $cloudHash.Add($_,"") }

                                if( Test-Path $LibPath ) {
                                                (Get-ChildItem $LibPath) | % { 
                                                                $vAppName = $_.Name
                                                                $vAppSKU = $vAppName.Substring(0,$vAppName.LastIndexOf('-'))
                                                                $vAppVersion = $vAppName.Replace("$vAppSKU-",'')
                                                                $currentVersions.Add($vAppSKU,$vAppVersion)
                                                                $report.Add($vAppSKU,$cloudHash.Clone()) 
                                                }
                                } Else {
                                                Write-Host -Foreground Red "ERROR: Unable to continue. Path $LibPath does not exist"
                                                Return
                                }
                }
                PROCESS {
                                Write-Verbose "in Show-VpodVersionsRest"
                                foreach( $cloud in $Clouds ) {
                                                $c = Get-CloudInfoFromKey -Key $cloud
                                                $cloudName = $c[0]
                                                $orgName = $c[1]
                                                $specifiedCatalogName = $c[2]
                                                
                                                $authHeader = $AuthHeaders[$cloud]
                                                $baseUrl = 'https://' + $cloudName + '/api'
                                                
                                                if( $UseCloudCatalogDefaultCatalogs ) {
                                                                Write-Verbose "`tUsing cloud-specific catalogs for $cloud"
                                                                Write-Verbose "`t`tconfigured catalog: $specifiedCatalogName"
                                                                if( $specifiedCatalogName.length -ne 0 ) {
                                                                                $theCatalogName = $specifiedCatalogName
                                                                } else{ 
                                                                                $theCatalogName = $CatalogName
                                                                }
                                                                Write-Host "`tchecking catalog $theCatalogName in $cloud"
                                                } else {
                                                                $theCatalogName = $CatalogName
                                                }
                                                
                                                try {
                                                                $restCatalogs = Get-VCDRestOrgInventory -BaseURL $baseURL -ResourceType 'catalog' -Auth $authHeader -OrgName $orgName
                                                                ## Enumerate the items in the specified catalog and stuff name, href into a hashtable
                                                                $theCatalog = (Get-VCDRestGet -URL $restCatalogs[$theCatalogName] -Auth $authHeader).Catalog
                                                                $catalogItems = @{}
                                                                foreach( $item in $theCatalog.CatalogItems.CatalogItem | where { ($_.NodeType -eq "Element") -and ($_.Type -eq "application/vnd.vmware.vcloud.catalogItem+xml") } ) {
                                                                                $catalogItems.Add($item.name,$item.href)
                                                                }
                                                                Write-Verbose "`tRead $theCatalogName catalog - contains $($catalogItems.count) items."

                                                                foreach( $vAppName in $catalogItems.Keys ) {
                                                                                if( $vAppName -like $VpodFilter ) {
                                                                                                $vAppSKU = $vAppName.Substring(0,$vAppName.LastIndexOf('-'))
                                                                                                $vAppVersion = $vAppName.Replace("$vAppSKU-",'')
                                                                                                Write-Verbose "DEBUG: $cloud $vAppSKU $vAppVersion"
                                                                                                #Add the information only if the SKU exists in the hashtable
                                                                                                if( ($vAppVersion -like 'v*') -and ($report.ContainsKey($vAppSKU)) ) {
                                                                                                                if( $ValidateTemplates ) {
                                                                                                                                Write-Verbose "Checking validity of $vAppName in $cloudName"
                                                                                                                                $catalogItem = (Get-VCDRestGet -URL $catalogItems[$vAppName] -Auth $authHeader).CatalogItem
                                                                                                                                $refVAppTemplate = $catalogItem.Entity.href
                                                                                                                                $vAppTemplate = (Get-VCDRestGet -URL $refVAppTemplate -Auth $authHeader).VAppTemplate
                                                                                                                                $status = $vAppTemplate.status
                                                                                                                                Write-Verbose "`t$status"
                                                                                                                                if( $status -ne "8" ) {
                                                                                                                                                #8 is the "resolved" state
                                                                                                                                                $vAppVersion += '!'
                                                                                                                                }
                                                                                                                }
                                                                                                                if( $vAppVersion -ne $currentVersions[$vAppSKU] ) {
                                                                                                                                $vAppVersion += '*'
                                                                                                                }
                                                                                                                $report[$vAppSKU][$cloud] += "$vAppVersion "
                                                                                                }
                                                                                } else {
                                                                                                Write-Verbose "$cloud discarding $vAppName by filter"
                                                                                }
                                                                }
                                                }
                                                catch {
                                                                Write-Host -Fore Red "ERROR: $theCatalogName not found in $orgName of $cloudName"
                                                }
                                }
                                
                                $out = @()
                                foreach( $vpod in ( $report.keys | Sort-Object ) ) {
                                                $line = "" | select (@('SKU') + $Clouds)
                                                $line.SKU = $vpod
                                                foreach( $cloud in $Clouds ) {
                                                                $line.($cloud) = $report[$vpod][$cloud]
                                                }
                                                $out += $line
                                }
                                #Note: Format-Table won't output more than 9 columns at a time
                                $out | Sort-Object -Property "SKU" | Format-Table -AutoSize
                }
} #Show-VpodVersionsRest


######## TESTING THE FOLLOWING

#quick and dirty
Function Test-VAppTemplateExistsInCatalog( $myTemplateName, $myCatalogName, $authHeader, $BaseURL )
{
                $templates = Get-VCDRestObject -Type "vAppTemplate" -Name $myTemplateName -Auth $authHeader -BaseURL $BaseURL
                foreach( $refTemplate in $templates ) { 
                                $template = (Get-VCDRestGet -URL $refTemplate -Auth $authHeader).VAppTemplate
                                $templateName = $template.Name
                                $refCatalogItem = ($template.Link | where { $_.rel -eq 'catalogItem' }).href
                                if( $refCatalogItem -ne $null ) {
                                                $refCatalog = ((Get-VCDRestGet -URL $refCatalogItem -Auth $authHeader).CatalogItem.Link | where { $_.rel -eq 'up' }).href
                                                $catalogItem = (Get-VCDRestGet -URL $refCatalogItem -Auth $authHeader).CatalogItem
                                                $catalogName = (Get-VCDRestGet -URL $refCatalog -Auth $authHeader).Catalog.Name
                                                Write-Verbose "$templateName owned by $catalogName"
                                                if( $catalogName -eq $myCatalogName ) { return $true }
                                } else {
                                                Write-Verbose "$templateName NOT owned (in progress?)"
                                }
                }
                return $false
}



Function Get-VCDRestVAppTemplateNetworkName {
<#
                Return the vAppNetwork Name from a vAppTemplate
#>
                [CmdletBinding()] 

                PARAM(
                                $Template = $(throw "-Template is required (href)"), 
                                $Auth = $(throw "-Auth is required"),
                                [string]$ApiVersion="29.0"
                )
                PROCESS {
                                try {
                                                if( $Template -match "catalogItem" ) {
                                                                Write-Verbose "Handling a CatalogItem"
                                                                Write-Verbose "$Template"
                                                                $catalogItem = (Get-VCDRestGet -URL $Template -Auth $Auth -ApiVersion $ApiVersion).CatalogItem
                                                                $refVAppTemplate = $catalogItem.Entity.href
                                                                Write-Verbose "$refVAppTemplate"
                                                } elseif( $Template -match "vAppTemplate" ) {
                                                                $refVAppTemplate = $Template                                
                                                } else {
                                                                Write-Host -ForegroundColor Red "Invalid template passed."
                                                                $refVAppTemplate = $null
                                                                return $false
                                                }
                                                
                                                Write-Verbose "Getting the vApp Template"
                                                $vAppTemplate = (Get-VCDRestGet -URL $refVAppTemplate -Auth $Auth -ApiVersion $ApiVersion).VAppTemplate
                                                $vAppTemplateName = $vAppTemplate.Name

                                                #retreive the vApp's network name from the vApp. There should only be ONE (and the special "none")
                                                $theAppNetworkName = $vAppTemplate.NetworkConfigSection.NetworkConfig[0].networkName

                                                if( $theAppNetworkName.length -eq 0) {
                                                                Write-Verbose "failed first NetworkName check, trying option 2"
                                                                ##SPECIAL CASE
                                                                #I have only seen this in HOL-1981 where someone totally messed up their networking and seem to have deleted the "none"
                                                                $theAppNetworkName = $vAppTemplate.NetworkConfigSection.NetworkConfig.networkName
                                                }
                                                if( $theAppNetworkName.length -eq 0) {
                                                                #still messed up, FAIL
                                                                Write-Host -ForegroundColor Red "ERROR: unable to read vApp network name from $vAppTemplateName"
                                                                Write-Host -ForegroundColor Red "NetworkConfig looks like this:"
                                                                Write-Host "$($vAppTemplate.NetworkConfigSection.NetworkConfig)"
                                                                return $null
                                                
                                                } else {
                                                                Write-Verbose "`tRead vApp network from vApp: $theAppNetworkName"
                                                }
                                } catch {
                                                Write-Host -ForegroundColor Red "UNHANDLED: failure while reading vApp network name from $vAppTemplateName template"
                                                return $null
                                }
                                
                                return $theAppNetworkName
                }
} #Get-VCDRestVAppTemplateNetworkName
