# checkbrowsers.ps1 22-April 2025
If ( $isWindows ) { $out = "C:\hol\checkbrowsers.txt"
} ElseIf ( $isLinux ) { $out = "/tmp/checkbrowsers.txt" }
Set-Content -Path $out -Value "" -NoNewline

If ( $isWindows ) {
	#45 Google Chrome "Do not send data" settings
	$chromeLocalState = "C:\users\Administrator\AppData\Local\Google\Chrome\User Data\Local State"
	$json = Get-Content -Path $chromeLocalState
	If ( $psVersion -eq 5 ) {
		$localState = ConvertFrom-Json20($Json)
	} Else {
		$localState = ConvertFrom-Json -InputObject $Json -AsHashTable
	}
	# Settings->Advanced-> "Automatically send usage statistics and crash reports to Google"
	$sendData = $localState.user_experience_metrics.reporting_enabled
	$chromePreferences = "C:\users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Preferences"
	$json = Get-Content -Path $chromePreferences
	If ( $psVersion -eq 5 ) {
		$preferences = ConvertFrom-Json20($Json)
	} Else {
		$preferences = ConvertFrom-Json -InputObject $Json
	}

	# Settings->Advanced-> "Automatically send some system information and page content to Google to help detect dangerous apps and sites"
	$sendData2 = $preferences.safebrowsing.scout_reporting_enabled
	If ( ($sendData -eq $true) -Or ($sendData2 -eq $true) ) {
		"FAIL~Google Chrome settings~Do not send data~Google Chrome is configured to send data over the Internet." | Add-Content $out
	} Else {
		"PASS~Google Chrome settings~Do not send data~Google Chrome is configured to not send data over the Internet."  | Add-Content $out
	}

	#44 Plugins: Allow all (and remember) - actually the best we can do with Chrome now is "Ask" and not "Block"
	$pluginSetting = $preferences.profile.default_content_setting_values.ppapi_broker
	If ( $pluginSetting ) {
		"FAIL~Google Chrome settings~Allow plugins~Google Chrome is configured to block all plugins." | Add-Content $out
	} Else {
		"PASS~Google Chrome settings~Allow plugins~Google Chrome is configured to ask about plugins."  | Add-Content $out
	}
	$ffDir = Get-ChildItem -Path "$Env:systemdrive\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release"
} ElseIf ( $isLinux ) { # check Firefox browser		
	$ffDir = Get-ChildItem -Path "/home/holuser/snap/firefox/common/.mozilla/firefox/*.default"
}

$userPrefs = Join-Path -Path $ffDir -ChildPath "prefs.js"
$prefs = Get-Content -Path $userPrefs
	
# Privacy & Security->Allow Firefox to send technical and interaction data to Mozilla
# user_pref("datareporting.healthreport.uploadEnabled", false);
$choice = $true
ForEach ( $line in $prefs ) {
	If ( $line -Like "*datareporting.healthreport.uploadEnabled*" ) {
		($junk, $conf) = $line.Split(",")
		If ( $conf -Like "*false*" ) { $choice = $false }
	}
}
If ( $choice ) {
	"FAIL~Firefox settings~Do not send data~Firefox is configured to send data over the Internet." | Add-Content $out
} Else {
	"PASS~Firefox settings~Do not send data~Firefox is configured to not send data over the Internet." | Add-Content $out
}
	
# Privacy & Security->Allow Firefox to install and run studies
# user_pref("app.shield.optoutstudies.enabled", false);
$choice = $true
ForEach ( $line in $prefs ) {
	If ( $line -Like "*app.shield.optoutstudies.enabled*" ) {
		($junk, $conf) = $line.Split(",")
		If ( $conf -Like "*false*" ) { $choice = $false }
	}
}
If ( $choice ) {
	"FAIL~Firefox settings~Run studies~Firefox is configured to allow studies." | Add-Content $out
} Else {
	"PASS~Firefox settings~Run studies~Firefox is configured to not allow studies." | Add-Content $out
}
	
	
#  Privacy & Security->Allow Firefox to send backlogged crash reports on your behalf
# user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", true);
$choice = $false
ForEach ( $line in $prefs ) {
	If ( $line -Like "*browser.crashReports.unsubmittedCheck.autoSubmit2*" ) {
		($junk, $conf) = $line.Split(",")
		If ( $conf -Like "*false*" ) { $choice = $true}
	}
}
If ( $choice ) {
	"FAIL~Firefox settings~Crash reports~Firefox is configured to send crash reports." | Add-Content $out
} Else {
	"PASS~Firefox settings~Crash reports~Firefox is configured to not send crash reports." | Add-Content $out
}
	
#25 vPodRouter Proxy working as expected
# Firefox does not respect the system setting so must check prefs.js
# user_pref("network.proxy.type", 0); is NO PROXY so this is bad. Setting should be absent if using system proxy.
# type 1 is manual settings which might be ok but we just want system proxy
# user_pref("network.proxy.no_proxies_on", "corp.vmbeans.com"); use the system settings
# type 2 is proxy configuration URL
# type 4 is Auto-detect proxy settings
$choice = $false
ForEach ( $line in $prefs ) {
	If ( $line -Like "*network.proxy.type*" ) {
		($junk, $conf) = $line.Split(",")
		If ( $conf ) { $choice = $true}
	}
}
If ( $choice ) {
	"FAIL~Firefox settings~Proxy~Firefox is configured to NOT use the system proxy." | Add-Content $out
} Else {
	"PASS~Firefox settings~Proxy~Firefox is configured to use the system proxy." | Add-Content $out
}

If ( $isWindows ) {
	$internetSettingsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
	$internetSettings = Get-Item $internetSettingsPath
	$proxyServer = $internetSettings.GetValue("ProxyServer")
	$proxyEnabled = $internetSettings.GetValue("ProxyEnable")
	"INFO~Proxy~Proxy System Settings~proxyEnabled: $proxyEnabled proxyServer: $proxyServer" | Add-Content $out
}
