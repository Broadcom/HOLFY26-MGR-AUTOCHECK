#43 Check for updates: Never (Windows task Google check for updates disabled)
# updates 06/10/2023 fixing up Windows command to run checking for Google update tasks

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

$googleUpdateTasks = @("GoogleUpdateTaskMachineCore*", "GoogleUpdateTaskMachineUA*")
$status = "Unknown"
Foreach ( $googleTask in $googleUpdateTasks ) {
	$checkScript = 'Powershell.exe -Command Get-ScheduledTask -TaskName $googleTask'
	Try {
		$errorVar = $null
		$rawout = RunWinCmd $checkScript ([REF]$result) $ipTarget 'Administrator' $password
		$output = $rawout.Replace("\r", "")
		$output = $output.Replace("'", "")
		#Write-Host "$output"
		If ( $output -Like "*Disabled*" ) { $status = "Disabled" }		
		If ( $output -Like  "*Running*" ) { $status = "Running" }		
		If ( $output -Like  "*Ready*" ) { $status = "Ready" }
		If ( $status -eq "Disabled" ) {
			If ( $result -ne "FAIL" ) { $result = "PASS" } # more than one loop
		} ElseIf ( ($status -eq "") -Or ($status -Like "*No MSFT_ScheduledTask objects found with property*") ) {
			Write-Logs "PASS" $target "Google Chrome updates" "No Google Chrome update tasks were found."
			Exit
		} Else {
			$result = "FAIL" 
		}
	} Catch {
		Write-Logs "FAIL" $target "Google Chrome updates" "Cannot check machine $hostName for Chrome updates." 
		Exit
	}
}

If ( $status -eq "Unknown" ) {
	Write-Logs "WARN" $target "Google Chrome updates" "Windows machine $hostName Chrome updates task state is $status. Please check manually."
} Else {
	# single PASS/FAIL log entry
	Write-Logs $result $target "Google Chrome updates" "Windows machine $hostName has Chrome updates task state as $status."
}	
	
