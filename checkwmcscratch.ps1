# 27-April 2024
$warn = $false
$volumes = Get-Volume | Where-Object {$_.DriveType -eq "Fixed"}
Foreach ($volume in $volumes) {
	If ( $volume.FileSystemLabel -eq 'System Reserved' ) { Continue }
	If ( $volume.DriveLetter -eq 'C' ) { Continue }
	If ( $volume.FileSystemLabel -eq "IDISK" ) { Continue }  # skip the iDisk
	If ( [byte][char]$volume.DriveLetter -ne 0 ) {
		$dRoot = $volume.DriveLetter + ":\"
		$items = Get-ChildItem -Path $dRoot
		Foreach ( $item in $items ) {
			$p = $dRoot + $item.Name
			$mode = [String]$item.Mode
			$sizeMB = "{0:N2} MB" -f ((Get-ChildItem $p -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
			$dir += $mode + "`t" + $item.Name + "`t" + $sizeMB + "`n"
		}
		$warn = $true
		$info = "Found additional volume: " + $volume.DriveLetter + ": " + $volume.FileSystemLabel + "`n" + $dir
		Write-Output "WARN~Cleanup~Scratch Drive~$info"
	} Else {
		$sizeGB = [math]::Round($volume.Size/1GB,2)
		If ( $sizeGB -gt 1.0 ) {
			$warn = $true
			Write-Output "WARN~Cleanup~Scratch Drive~Found additional volume with no drive letter and size: $sizeGB"
		}
	}
}
If ( -Not $warn ) {
	Write-Output "PASS~Cleanup~Scratch Drive~No scratch drives found."
}