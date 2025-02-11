$labStartupFunctions = "..\..\labstartup\LabStartupFunctions.psm1"
$HashAlgorithm = 'SHA256' #one of the supported types: MD5, SHA1, SHA256, SHA384, SHA512
$lsfHash = Get-FileHash -Path $labStartupFunctions -Algorithm $HashAlgorithm
$lsFunctionsHash = $lsfHash.Hash.ToLower()
Write-Output "lsFunctionsHash: $lsFunctionsHash"