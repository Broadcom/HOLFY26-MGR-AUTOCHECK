# checkurls.ps1 23-April 2025

# updated 7/2/2020 added better SSL Cert expiration message using licenseExpiration.txt
# updated 7/2/2020 single FAIL for Chrome browser history. Multiple line detail listing history URLs
# updated 4/16/2021 numerous updates to support Firefox on LMC
# updated 4/19/2021 bug fix for Firefox history and check for running firefox process
# updated 4/27/2021 bug fix to not overwrite logs and correct log entry
# updated 7/27/2021 corrected several bugs with testing live bookmarks
# updated 11/30/2021 corrected check for Firefox process
# updated 1/24/2022 corrected URL pattern matching to find port number
# updated 4/11/2022 added SQLite code on Windows to check Firefox bookmarks and use testsslcert.py instead.
# updated 6/20/2022 $vPodYear not $labYear
# updated 6/24/2022 calling testsslcert.py with python3 on Linux so chmod a+x is not needed

# need this stuff at a minumum

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
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

# DEBUG - clear the output files
#Set-Content -Path $csvFile -Value "" -NoNewline # overwrite existing csv file
#Set-Content -Path $logFile -Value "" -NoNewline # overwrite existing log file

#####Check SSL certificates on provided links: using URLS file from config.ini
#####Will add browser bookmarks for checking as well

Write-Output "Checking URLs..."

Set-Variable -Name "URLs" -Value $(Read-ConfigIntoArray "RESOURCES" "URLs")
#ForEach ( $url in $URLs ) { Write-Host $url }

$urlsToTest = @()
$allURLs = @()
Foreach ($entry in $URLs) {
	#Write-Host "entry: $entry"
	($url,$response) = $entry.Split(",")
	If (!$response) { # 8/20/2020 WARN if empty response
		Write-Logs "WARN" "URLs" "Response Match" "$url test has no response to match. Please add a response to check."
	}
	$allURLs += $url
	 If( $url -match 'https' ) { 
	 	$urlsToTest += $url
	 } 
}
#ForEach ( $url in $urlsToTest ) { Write-Host $url }

##############################################################################
##### Check Browser Bookmarks against URLs in config.ini
##############################################################################

$bookmarks = @()

# for Firefox need PS module PSSQLite

If ( $WMC ) { 
	#$browser = "Chrome"
	If ( $browser -eq "Chrome" ) {
		$bookmarksPath = "$mc" + '/Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/Bookmarks'
	} ElseIf ( $browser -eq "Firefox" ) {
		$bookmarksPath = "$mc/Users/Administrator/AppData/Roaming/Mozilla/Firefox/Profiles/*.default-release/places.sqlite"
	}
	If (!(Test-Path -Path $bookmarksPath)) { Write-Logs "FAIL" "autocheck" "bookmarks" "Unable to check $browser bookmarks"
	} ElseIf ( $browser -eq "Chrome") {
	  $output = @('first')
	  If ( $psVersion -eq 5 ) {
		$json = Get-Content $bookmarksPath
		$output = ConvertFrom-Json20($json)
		$jsonObject = $output.roots.bookmark_bar.children
		[Array]$bookmarks = $jsonObject.url | Sort -Unique
		# get the URLs out of the bookmark folders
		Foreach ( $obj in $jsonObject ) {
			If ( $obj.type -match 'folder' ) {
				$bookmarks += $obj.children.url | Sort -Unique
			}
		}
	  } Else {		# PowerShell version 7
		[String]$json = Get-Content $bookmarksPath
		$output = ConvertFrom-Json -InputObject $json -NoEnumerate
		ForEach ( $entry in $output.roots.bookmark_bar.children.children ) {
			If ( $entry.type -eq 'url' ) {
				$bookmarks += $entry.url
			}
		}
		ForEach ( $entry in $output.roots.bookmark_bar.children ) {
			If ( $entry.type -eq 'url' ) {
				$bookmarks += $entry.url
			}
		}
	  }
	} ElseIf ( $browser -eq "Firefox" ) {
		$ffDbPath = Get-ChildItem -Path "$mc/Users/Administrator/AppData/Roaming/Mozilla/Firefox/Profiles/*.default-release/places.sqlite"
		$allPlaces = Invoke-SqliteQuery -DataSource $ffDbPath -Query “SELECT url FROM moz_places”
		$bookmarkIDs = Invoke-SqliteQuery -DataSource $ffDbPath -Query "SELECT fk FROM moz_bookmarks WHERE fk NOT NULL"
		$varQuery = "SELECT url FROM moz_places WHERE id = var"
		ForEach ( $id in $bookmarkIDs) {
		$bmark = [String](Invoke-SqliteQuery -DataSource $ffDbPath -Query $varQuery.Replace('var', $id.fk))
		If ( ($bmark -NotLike "*mozilla.org*") -And ($bmark -NotLike "*ubuntu*") -And  ($bmark -NotLike "*debian*") ) {
			$bmark = $bmark.Replace('@{url=', '')
			$bookmarks += $bmark.Replace('}', '')
		}
	}
	}
} ElseIf ( $LMC ) {
	$ffDbPath = Get-ChildItem -Path "$mc/home/holuser/snap/firefox/common/.mozilla/firefox/*.default/places.sqlite"
	$ffcmd = "ps -ef | grep /usr/lib/firefox | grep -v grep"
	$ff = remoteLinuxCmdLMC "console" "holuser" $password $ffcmd
	#Write-Host ".${ff}."
	While ( $ff  -ne "" ) {
		Write-Output "Please exit Firefox. Cannot perform Firefox checks while Firefox is running."
		Start-Sleep $sleepSeconds
		$ff = remoteLinuxCmdLMC "console" "holuser" $password $ffcmd
	}
	$allPlaces = Invoke-SqliteQuery -DataSource $ffDbPath -Query “SELECT url FROM moz_places”
	$bookmarkIDs = Invoke-SqliteQuery -DataSource $ffDbPath -Query "SELECT fk FROM moz_bookmarks WHERE fk NOT NULL"
	$varQuery = "SELECT url FROM moz_places WHERE id = var"
	ForEach ( $id in $bookmarkIDs) {
		$bmark = [String](Invoke-SqliteQuery -DataSource $ffDbPath -Query $varQuery.Replace('var', $id.fk))
		If ( ($bmark -NotLike "*mozilla.org*") -And ($bmark -NotLike "*ubuntu*") -And  ($bmark -NotLike "*debian*") ) {
			$bmark = $bmark.Replace('@{url=', '')
			$bookmarks += $bmark.Replace('}', '')
		}
	}
}

Write-Output "Checking $browser Bookmarks in $configIni ..."
$function = "bookmarks"
Foreach ($bookmark in $bookmarks) {
	If ( $bookmark -Like "*stg*-0*" ) { Continue } # skip FreeNAS?
	If ( $bookmark -Like "*10.0.0.60*" ) { Continue } # skip FreeNAS? (not https so will skip anyway)
	If ( $bookmark -Like "*vcsa*.$dom:5480*" ) { Continue } # skip vCenter VAMI?
		
	$h = [regex]::Replace($bookmark, "https://([a-z\.0-9\-]+).*", '$1')
	$found = $false
	Foreach( $url in $allURLs ) {
		#Write-Output "bookmark: $bookmark url: $url h: $h"
		If ( ($url -Like "*$bookmark*") -Or ($bookmark -Like "*$url*") ) {
			$found = $true
			Write-Logs "PASS" $bookmark $function "$browser bookmark was found in config.ini URLs"
			Break
		}
	}
	If ( $found -eq "skip" ) { Continue } # a similar URL was found in the config.ini
	If ( -Not $found ) {
		#Write-OutPut $bookmark
		$allURLs += $bookmark
		#if the port responds and they are not checking then that is a warn.
		$f = $bookmark.Split(":")
		$s = $f[1].Split("/")
		$server = $s[2]
		If ( $bookmark -Like "http*:*:*//*" ) {
			($port, $junk) = $f[2].Split("/")
		} ElseIf ( $f[0] -eq "https" ) {
			$port = "443"
		} Else { $port = "80" }
		#Write-Output "port: $port"
		#Write-Output "Testing $bookmark server: $server on port: $port "
		Test-TcpPortOpen -Server $server -Port $port -Result ([REF]$result)
		If ( $result -eq "success" ) {
			Write-Logs "WARN" $bookmark $function "Live $browser bookmark was NOT found in config.ini for LabStartup testing. LabStartup should test every URL if available at start of lab."
			If( $url -match 'https' ) { # Add this browser bookmark for SSL certificate checking
				$urlsToTest += $bookmark
			}
		} Else {
			# try a web request here
			Test-URL -Url $bookmark -Result ([REF]$result)
			If ( $result -eq "success") {
				Write-Logs "WARN" $bookmark $function "Live $browser bookmark was NOT found in the config.ini for LabStartup testing. LabStartup should test every URL if available at start of lab."
			} Else {
				Write-Logs "INFO" $bookmark $function "No response from $browser bookmark NOT found in the config.ini."
			}
		}
	}
}
# End Check Browser Bookmarks in config.ini

##############################################################################
##### Check SSL Certificates Expiration
##############################################################################

Write-Output "Checking SSL certificate expiration..."
$function = "SSL Certificate"


#Disable SSL certificate validation checks... it's a Lab!
$scvc = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$testedHosts = ""
Foreach( $url in $urlsToTest ) {
	$h = [regex]::Replace($url, "https://([a-z\.0-9\-]+).*", '$1')
	If ( $testedHosts.Contains($h) ) { Continue } # only need to test once
	If( $url -like "https*" ) {
		$status = Invoke-Expression "python3 $PSScriptRoot/testsslcert.py $url $vPodYear"
		#Write-Host $status
		($junk, $message) = $status.Split(':')
		If ( $status -Like "*PASS*" ) {   Write-Logs "PASS" $url $function $message
		} ElseIf ( $status -Like "*EARLY*" ) { Write-Logs "FAIL" $url $function $message
		} Else { Write-Logs "FAIL" $url $function $message }
		# If ( $isWindows ) { checkSslCert $url }  # This never works because PowerShell can't deal with SSL Certificate checking
	}
	$testedHosts += $h
} # End Check and report SSL Certificates


#40 Browser history & cache cleared (well - at least history only contains lab URLs)
Write-Output "Checking $browser History..."
$historyURLs = @{}
$historyHosts = @{}
$allHosts = @{}
$historyCSV = "/tmp/history.csv"
$browser = "Chrome"
If ( ( $WMC ) -And ( $browser -eq "Chrome" ) ) {
	$McHistoryCSV = "$mc/Temp/history.csv"
	Copy-Item "$PSScriptRoot/ChromeHistoryView.exe" "$mc/Temp"
	$chromeHistoryCMD = "C:\Temp\ChromeHistoryView.exe /scomma C:\Temp\history.csv /sort 0"
	$output = RunWinCmd $chromeHistoryCMD ([REF]$result) 'mainconsole' 'Administrator' $password
	While ( -Not (Test-Path $McHistoryCSV) ) { Start-Sleep $sleepSeconds }
	Copy-Item $McHistoryCSV $historyCSV
	Remove-Item "$mc/Temp/ChromeHistoryView.exe"
	Remove-Item "$mc/Temp/history.csv"
} Else {
	$history = @()
	ForEach ( $entry in $allPlaces ) {
		$place = [String]$entry
		If ( ($place -Like "*mozilla.org*") -Or ($place -Like "*ubuntu*") -Or  ($place -Like "*debian*") ) { Continue }
		$place = $place.Replace('@{url=', '')
		$place = $place.Replace('}', '')
		$found = $False
		ForEach ( $url in $bookmarks ) { 
			If ( $url -eq $place ) { 
				$found = $True 
				Break
			}
		}
		If ( -Not $Found ) { 
			If ( @($history) -Like "*$place*" ) { Continue 
			} Else { $history += $place }
		}
	}
	Set-Content -Path $historyCSV -Value "" -NoNewline
	ForEach ( $url in $history ) { 
		"$url," | Add-Content -Path $historyCSV
	}	
}

$output = Get-Content -Path $historyCSV

$prevUrl = ''
Foreach ( $line in $output ) {
	If ( $line -Like "file:*" ) { Continue }
	If ( $line -Like "*$dom*" ) { Continue }
	If ( $line -Like "*192.168.*" ) { Continue }
	$fields = $line.Split(",")
	If ( $fields[0] -eq "URL" ) { Continue } #skip the column header line
	If ( $fields[0] -Like "*?*" ) {
		($url, $junk) = $fields[0].Split("?")
	} Else { $url = $fields[0] }
	If ( $url -eq $prevUrl ) { Continue }
	$historyURLs[$url] = $fields[0]
	If ( $url -Like "*/*" ) {
		($junk,$keep) = $url.Split('/')
		($h,$junk) = $keep[1].Split(':')
	} Else { $h = $url }
	If ( $historyHosts[$h] ) {
		$historyHosts[$h] +=  "`n" + $url
	} Else {
		$historyHosts[$h] += $url
	}
	$prevUrl = $url
}

Foreach ( $url in $allURLs ) {
	Try {
		($junk,$keep) = $url.Split('/')
		$h = $keep[1]
		$allHosts[$h] = $url
	} Catch {}
}

$urls = ''
Foreach ( $historyHost in $historyHosts.keys ) {
	If ( $historyHost -Like "*-01a*" ) { Continue }
	$url = $historyHosts[$historyHost]
	
	#Write-Output "allHosts[$historyHost]:" $allHosts[$historyHost]
	If ( -Not $allHosts[$historyHost] ) {
		#Write-Output "historyHost: $historyHost not found in allHosts"
		$urls += "`n" + $url
	}
}

#Write-Output $historyHost
If ( $urls ) {
	Write-Logs "FAIL" $browser "Browser History" "Please clear $browser browser history: $urls"
} Else {
	Write-Logs "PASS" $browser "Browser History" "$browser browser history looks good. Thanks!"
}
