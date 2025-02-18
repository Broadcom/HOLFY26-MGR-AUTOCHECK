# 24-April 2024
# post process AutoCheck results CSV detail file (autocheck-detail-{vApp-Name}.csv)
# corrected logic in loop to process bare lines for lists of files, etc...
# using Test-Path now because it works on Linux and Windows
# creating empty status detail files if needed
# correct html.zip path for LMC
# added logic to handle 0 FAILs and 0 WARNs, i.e., SUCCESS
# if run through Toolbox, FAIL if AutoCheck artifacts are present. AutoCheck should NOT be run on the gold version.
# allowed AutoCheck.log and AutoCheck.err in the hol folder which are normal when running through Toolbox

$autocheckModulePath = "$PSSCriptRoot\autocheckfunctions.psm1"
If( Test-Path $autocheckModulePath ) { Import-Module $autocheckModulePath -DisableNameChecking }

#$result must be created in order to pass as reference for looping
$result = ''

##############################################################################
##### BEGIN HERE
##############################################################################

# expand the $PSScriptRoot\HTML.zip to $logDir
$htmlZip = Join-Path -Path $PSScriptRoot -ChildPath "html.zip"
Expand-Archive -Path $htmlZip -DestinationPath $logDir -Force

$htmlFile = Join-Path $logDir "autocheck-$vPodName.html"

# just create the wholetop-level report page for now
# search and replace after processing the CSV.

$htmlReport = @"
<!DOCTYPE html>
<html lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><style type="text/css"></style>
  <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>#VPODNAME# AutoCheck</title>
  <link rel="stylesheet" href="./HTML/clr-ui.css">
  <link rel="stylesheet" href="./HTML/clr-icons.min.css">
  <link rel="stylesheet" href="./HTML/styles.css">
</head>
<body>

<div class="main-container">

<div class="content-container">
    <div class="content-area">
	    <div style="max-width: 1500px; min-width: 900px; margin: 0 auto;">
		<h1>AutoCheck Report</h1>

		<div class="row">
			<div class="col-xs-12">
				<div class="card">
					<div class="card-block">
						<h2 class="card-title">#VPODNAME#</h2>
					</div>
					<div class="card-block">
						<div class="card-text">	
							<div class="alert alert-danger alert-app-level" style="overflow-y:hidden;">
								<div class="alert-items">
									<div class="alert-item">
										<div class="alert-icon-wrapper">
											<clr-icon class="alert-icon" shape="exclamation-circle"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>exclamation-circle</title>

            </svg>
											<svg version="1.1" viewBox="0 0 36 10" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>exclamation-circle</title>
											</svg></clr-icon>
										</div>
										<span class="alert-text">
											<strong>Needs Review</strong>
										</span>
									</div>
								</div>
							</div>

							
						</div>
					</div>

					<div class="card-block">
						<div class="card-title">
							Details
						</div>
						<div class="alert alert-success">
							<div class="alert-items">
								<div class="alert-item">
									<div class="alert-icon-wrapper">
										<clr-icon class="alert-icon" shape="check-circle"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>check-circle</title>

            </svg><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>check-circle</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M30,18A12,12,0,1,1,18,6,12,12,0,0,1,30,18Zm-4.77-2.16a1.4,1.4,0,0,0-2-2l-6.77,6.77L13,17.16a1.4,1.4,0,0,0-2,2l5.45,5.45Z"></path>
            </svg></clr-icon>
									</div>
									<span class="alert-text">
								<span>Pass:</span>
								<strong>#PASS#</strong>
							</span>
									<div class="alert-actions">
										<a id="auto-check-filter-pass" class="alert-action" href="./HTML/PASS.html" target="_blank">View</a>
									</div>
								</div>
							</div>
						</div>

						<div class="alert alert-danger">
							<div class="alert-items">
								<div class="alert-item">
									<div class="alert-icon-wrapper">
										<clr-icon class="alert-icon" shape="exclamation-circle"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>exclamation-circle</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm-1.49,6a1.49,1.49,0,0,1,3,0v6.89a1.49,1.49,0,1,1-3,0ZM18,25.5a1.72,1.72,0,1,1,1.72-1.72A1.72,1.72,0,0,1,18,25.5Z"></path>
            </svg><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>exclamation-circle</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm-1.49,6a1.49,1.49,0,0,1,3,0v6.89a1.49,1.49,0,1,1-3,0ZM18,25.5a1.72,1.72,0,1,1,1.72-1.72A1.72,1.72,0,0,1,18,25.5Z"></path>
            </svg></clr-icon>
									</div>
									<span class="alert-text">
										<span>Fail:</span>
										<strong>#FAIL#</strong>

									</span>
									<div class="alert-actions">
										<a id="auto-check-filter-fail" class="alert-action" href="./HTML/FAIL.html" target="_blank">View</a>
									</div>
								</div>
							</div>
						</div>
						
						
						<div class="alert alert-warn">
							<div class="alert-items">
								<div class="alert-item">
									<div class="alert-icon-wrapper">
										<clr-icon class="alert-icon" shape="warning-standard"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>warning-standard</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M34.6,29.21,20.71,3.65a3.22,3.22,0,0,0-5.66,0L1.17,29.21A3.22,3.22,0,0,0,4,34H31.77a3.22,3.22,0,0,0,2.83-4.75ZM16.6,10a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,29.85a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,29.85Z"></path>
            </svg><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>warning-standard</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M34.6,29.21,20.71,3.65a3.22,3.22,0,0,0-5.66,0L1.17,29.21A3.22,3.22,0,0,0,4,34H31.77a3.22,3.22,0,0,0,2.83-4.75ZM16.6,10a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,29.85a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,29.85Z"></path>
            </svg></clr-icon>
									</div>
									<span class="alert-text">
										<span>Warn:</span>
										<strong>#WARN#</strong>
									</span>
									<div class="alert-actions">
										<a id="auto-check-filter-warn" class="alert-action" href="./HTML/WARN.html" target="_blank">View</a>
									</div>
								</div>
							</div>
						</div>
						
						
						<div class="alert alert-info">
							<div class="alert-items">
								<div class="alert-item">
									<div class="alert-icon-wrapper">
										<clr-icon class="alert-icon" shape="info-circle"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>warning-standard</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M34.6,29.21,20.71,3.65a3.22,3.22,0,0,0-5.66,0L1.17,29.21A3.22,3.22,0,0,0,4,34H31.77a3.22,3.22,0,0,0,2.83-4.75ZM16.6,10a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,29.85a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,29.85Z"></path>
            </svg><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>warning-standard</title>

                <path class="clr-i-solid clr-i-solid-path-1" d="M34.6,29.21,20.71,3.65a3.22,3.22,0,0,0-5.66,0L1.17,29.21A3.22,3.22,0,0,0,4,34H31.77a3.22,3.22,0,0,0,2.83-4.75ZM16.6,10a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,29.85a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,29.85Z"></path>
            </svg></clr-icon>
									</div>
									<span class="alert-text">
										<span>Info:</span>
										<strong>26</strong>
									</span>
									<div class="alert-actions">
										<a id="auto-check-filter-info" class="alert-action" href="./HTML/INFO.html" target="_blank">View</a>
									</div>
								</div>
							</div>
						</div>						

						
						<div class="alert alert-success">
							<div class="alert-items">
								<div class="alert-item">
									<div class="alert-icon-wrapper">
										<clr-icon class="alert-icon" shape="info-pass"><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>info-circle</title>

            </svg><svg version="1.1" viewBox="0 0 36 36" preserveAspectRatio="xMidYMid meet" class="has-solid" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" focusable="false" role="img">
                <title>info-circle</title>

            </svg></clr-icon>
									</div>
									<span class="alert-text">
										<span>Inventory Utilization Report</span>
									</span>
									<div class="alert-actions">
										<a id="auto-check-filter-pass" class="alert-action" href="./HTML/invutilrpt.txt" target="_blank">View</a>
									</div>
								</div>
							</div>
						</div>
					</div>
					<div class="card-block">

					</div>
					
				</div>
			</div>
		</div>


  </div>

</div>

<div id="file-modal-backdrop"></div>
<div id="file-modal">
	<div class="file-modal-dialog">
		<h2 class="mt-0 mb-1"></h2>
		<iframe width="100%" src="./HTML/saved_resource.html"></iframe>
		<div id="file-modal-close">×</div>
	</div>
</div>

</div></div></body></html>
"@
Set-Content -Path $htmlFile -Value $htmlReport -NoNewline

$source = Get-Content $csvDetailFile
$silent = New-Item -Path $logDir -Name "HTML" -ItemType "directory" -Force
$detailHead = @"
<!DOCTYPE html>
<html lang="en">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <style type="text/css"></style>
    <meta name="viewport"
        content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>#VPODNAME# #STATUS#</title>
    <link rel="stylesheet" href="./clr-ui.css">
    <link rel="stylesheet" href="./HTML/clr-icons.min.css">
    <link rel="stylesheet" href="./HTML/styles.css">
</head>
"@

$tableStart = @"
<div id="AutoCheck-details-table" class="row">
    <div class="col-xs-12">
      <h2>AutoCheck Details</h2>
      <table class="table" style="width: 100%;">
        <thead>
        <tr>
		  <th class="left"> Count </th> 
          <th class="left">Test Name</th>
		  <th class="left">Target</th>
          <th class="left">Status</th>
          <th class="left">Details/Logs</th>
          <th class="left">Notes</th>
        </tr>
        </thead>
        <tbody>
		<tr>
"@
$linefmt = @"
 <tr>
		<td class="left" style="vertical-align: middle !important;">
		<div class="btn-group btn-primary btn-icon">
		<a title="View" class="btn" href="#ID=1">
		#COUNT# </a>
        </div>
		</td>
"@
$fmt = '<td class="left" style="vertical-align: middle !important;">'
$passFmt = @"
<SPAN STYLE="color: Green;">
"@
$failFmt = @"
<SPAN STYLE="color: Red;">
"@
$warnFmt = @"
<SPAN STYLE="color: Orange;">
"@
$infoFmt = @"
<SPAN STYLE="color: Blue;">
"@
Remove-Item "$logDir\HTML\*.html"
# TODO: create custom objects for PASS, FAIL, WARN and INFO ??
$passCtr = 0
$failCtr = 0
$warnCtr = 0
$infoCtr = 0

ForEach ( $line in $source ) {
	If ( $line -NotMatch '\d\d/\d\d/\d\d\d\d ' ) {  # continuation record
		#Write-Output $line
		"$line<br>" | Add-Content -Path $fPath
		Continue
	} ElseIf (-not ([string]::IsNullOrEmpty($fPath))) { # new record so close the entry from the previous
		"</td>$fmt$field</td>" | Add-Content -Path $fPath
		"</tr>" | Add-Content -Path $fPath
	}
	$fields = $line.Split(',')
	If ( $fields[4] ) {
		$target = $fields[2]
		$testName = $fields[3]
		$status = $fields[4]
		$status = $status.Replace("['", "")
		$detail = $fields[5]
		$fPath = "$logDir/HTML/$status.html"
		If ( ! (Test-Path $fPath) ) { 
			$detHead1 = $detailHead -Replace '#VPODNAME#', $vPodName
			$detHead2 = $detHead1 -Replace '#STATUS#', $status
			Set-Content -Path $fPath -Value $detHead2
			$tableStart | Add-Content -Path $fPath
		}
		If ( $status -eq "PASS" ) {
			$PASS = $true
			$passCtr++
			$linefmt -Replace '#COUNT#', $passCtr | Add-Content -Path $fPath
			$lineEnd = "$fmt$passFmt$status</td>"
		} ElseIf ( $status -eq "FAIL" ) {
			$FAIL = $true
			$failCtr++			
			$linefmt -Replace '#COUNT#', $failCtr | Add-Content -Path $fPath
			$lineEnd = "$fmt$failFmt$status</td>"
		} ElseIf ( $status -eq "WARN" ) {
			$WARN = $true
			$warnCtr++			
			$linefmt -Replace '#COUNT#', $warnCtr | Add-Content -Path $fPath
			$lineEnd = "$fmt$warnFmt$status</td>"
		} ElseIf ( $status -eq "INFO" ) {
			$INFO = $true
			$infoCtr++
			$linefmt -Replace '#COUNT#', $infoCtr | Add-Content -Path $fPath
			$lineEnd = "$fmt$infoFmt$status</td>"
		}

	}
	"$fmt$testName</td>" | Add-Content -Path $fPath
	"$fmt$target</td>" | Add-Content -Path $fPath
	$lineEnd | Add-Content -Path $fPath
	"$fmt$detail <br>" | Add-Content -Path $fPath
}

# create empty status detail pages if needed
$statusLabels = @("PASS", "FAIL", "WARN", "INFO")
ForEach ( $status in $statusLabels ) {
	$fPath = "$logDir/HTML/$status.html"
	If ( ! (Test-Path $fPath) ) { 
		$detHead1 = $detailHead -Replace '#VPODNAME#', $vPodName
		$detHead2 = $detHead1 -Replace '#STATUS#', $status
		Set-Content -Path $fPath -Value $detHead2
		$tableStart | Add-Content -Path $fPath
	}
}

# replace as needed in the top-level html
$newHtmlReport = Get-Content -Path $htmlFile
$newHtmlReport = $newHtmlReport -Replace '#VPODNAME#', $vPodName
$newHtmlReport = $newHtmlReport -Replace '#PASS#', $passCtr
$newHtmlReport = $newHtmlReport -Replace '#FAIL#', $failCtr
If ( $failCtr -eq 0 -And $warnCtr -eq 0 ) {
	$newHtmlReport = $newHtmlReport -Replace '<strong>Needs Review</strong>', '<strong>Passed</strong>'
	$old = '<div class="alert alert-danger alert-app-level" style="overflow-y:hidden;">'
	$new = '<div class="alert alert-success alert-app-level" style="overflow-y:hidden;">'
	$newHtmlReport = $newHtmlReport -Replace $old, $new
}
$newHtmlReport = $newHtmlReport -Replace '#WARN#', $warnCtr
$newHtmlReport = $newHtmlReport -Replace '#INFO#', $infoCtr
$quiet = Set-Content -Path $htmlFile -Value $newHtmlReport
