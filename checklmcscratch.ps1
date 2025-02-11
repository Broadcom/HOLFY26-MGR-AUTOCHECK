# checklmcscratch.ps1 27-March 2024
$mounts = @("Mounted",
	"/dev",
	"/run",
	"/dev/shm",
	"/run/lock",
	"/sys/fs/cgroup",
	"/snap/",
	"/boot/efi",
	"/run/user/1000",
	"/media/cdrom0",
	"/mnt/idisk/")
	
If ( $logDir -Like "*idisk*" ) { $dCount = 6
} Else { $dCount = 4 }

$drives = Get-ChildItem -Path /dev/sd* -Name
If ( $drives.Count -gt $dCount ) {
	$output = Invoke-Expression "df -h"
	ForEach ( $line in $output ) {
		#Write-Host $line
		$found = $false
		($dev, $sizeGB, $used, $avail, $use, $mount) = $line -split '\s+' -match '\S'
		If ( $mount -eq '/' ) { Continue }			
		If ( $line -Like "*cdrom0*" ) { Continue }
		If ( $line -Like "*idisk*" ) { Continue }
		ForEach ( $mnt in $mounts ) {
			If ( $mount -Like "*$mnt*") {
				$found = $true
				Break
			}
		}
		If ( -Not $found ) {
			Write-Output "WARN~Cleanup~Scratch Drive~Found additional volume $mount with size: $sizeGB"
		}
	}
} Else {
	Write-Output "PASS~Cleanup~Scratch Drive~No scratch drives found."
}
