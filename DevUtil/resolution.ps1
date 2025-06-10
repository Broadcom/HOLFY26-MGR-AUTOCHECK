$autocheckModulePath = Join-Path $PSSCriptRoot -ChildPath "../autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }
Else {
	Write-Host "Abort."
	Exit
}

#$result must be created in order to pass as reference for looping
$result = ''

#64 Main Console screen resolution = 1024 x 768
Write-Output "Checking screen resolution..."
# 2/5/2020 increasing default screen resolution to 1280 x 800
$defaultScreenWidth = 1280
$defaultScreenHeight= 800

$pass = $true
If ( $isWindows ) {

	[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	$screenSize = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize
	If( ($screenSize.Width -ne $defaultScreenWidth) -Or ($screenSize.Height -ne $defaultScreenHeight) ) {
		$pass = $false
	}
} ElseIf ( $isLinux ) {
	$resCmd = "xrandr | grep current | cut -f2 -d ','"
	$fields = (Invoke-Expression $resCmd).Split()
	$width = $fields[2]
	$height = $fields[4]
	If ( $width -ne $defaultScreenWidth -Or $height -ne $defaultScreenHeight) {
		$pass = $false
		$screenSize = "$width x $height"
	}
}

If ( $pass ) {
	Write-Logs "PASS" "Main Console" "Screen Resolution" "Main Console has correct $defaultScreenWidth x $defaultScreenHeight screen resolution."
} Else {
	Write-Logs "FAIL" "Main Console" "Screen Resolution" "Main Console has non-standard screen resolution of $screenSize"
}
