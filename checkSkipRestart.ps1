# 12-April 2024
# #65 Include skipRestart utility if Win7/2K3/2k8
# This check is only needed for old Windows OSes that display a restart dialog pop-up when 
# switching between processors (typically Intel and AMD)
# typically as osf 2024 it will not be called.

Function checkOutput ( [String]$out, [String]$f ) {
	If ( $out -Like "*False*" ) {
		Write-Logs "FAIL" $target "skipRestart Win7/2K3/2k8" "$hostName requires the skipRestart utility $f File Not Found."
		Exit 0
	}
}

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

$hostName = $args[0]
$ipTarget = $args[1]

$target = $hostname + "(" + $ipTarget + ")"

# skipRestart paths - these are the files that need to be present
$skipRestartPaths = @("C:\hol\skipRestart.bat",
"C:\hol\skipRestart.ps1",
"C:\ProgramData\Microsoft\Windows\'Start Menu'\Programs\StartUp\skipRestart.lnk")

# Process of elimination. If any of these files are missing, it is a FAIL and the script exits.

# cannot do variable substitution here so must check each file individually
$wcmd = 'PowerShell.exe -Command `"Test-Path C:\hol\skipRestart.ps1`"'
$rawout = RunWinCmd $wcmd ([REF]$result) $ipTarget 'Administrator' $password
checkOutput $rawout "C:\hol\skipRestart.ps1"

$wcmd = 'PowerShell.exe -Command `"Test-Path C:\hol\skipRestart.bat`"'
Write-Host $wcmd
$rawout = RunWinCmd $wcmd ([REF]$result) $ipTarget 'Administrator' $password
Write-Host $rawout
checkOutput $rawout "C:\hol\skipRestart.bat"

# thanks to the space in Windows - this one is even more complicated.
$wcmd = @"
"PowerShell.exe -Command \"Test-Path C:\ProgramData\Microsoft\Windows\'Start Menu'\Programs\StartUp\skipRestart.lnk\""
"@
"/usr/bin/python3 /home/holuser/autocheck/runwincmd.py $ipTarget Administrator $password $wcmd" | Set-Content /tmp/runcmd.sh
$rawout = Invoke-Expression -Command "/bin/sh /tmp/runcmd.sh" -ErrorVariable errorVar
#Write-Host $rawout
checkOutput $rawout "C:\ProgramData\Microsoft\Windows\'Start Menu'\Programs\StartUp\skipRestart.lnk"

# it we make it to here then all 3 files are present and the machine passes
Write-Logs "PASS" $target "skipRestart Win7/2K3/2k8" "skipRestart utility found on $hostName"


