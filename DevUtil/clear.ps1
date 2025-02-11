
$acheckFiles = "/tmp/AutoCheck/*"
$zipFiles = "/tmp/autocheck*.zip"
$html = "autocheck-HOL-*.html"


If ( Test-Path $acheckFiles ) {
	Remove-Item $acheckFiles -Force -Confirm:$false -Recurse
}
If ( Test-Path $acheckFiles ) {
	Remove-Item $zipFiles -Confirm:$false
}

If ( Test-Path "/wmchol/Temp/$html" ) {
	Remove-Item "/wmchol/Temp/$html"
	Remove-Item -Recurse "/wmchol/Temp/HTML"
	Exit 0
}

If ( Test-Path "/lmchol/Temp/$html" ) {
	Remove-Item "/lmchol/Temp/$html"
	Remove-Item -Recurse "/lmchol/Temp/HTML"
}


