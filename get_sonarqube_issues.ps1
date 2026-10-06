# This script fetches all issues, security hotspots, and duplications from a public SonarCloud project and saves them to markdown files.

# SonarCloud project key
$projectKey = "DangerDawgAU_EIDAuthentication"
$sonarCloudUrl = "https://sonarcloud.io"

# Create a directory to store the issues, hotspots, and duplications
$outputDir = "sonarqube_issues"
if (Test-Path -Path $outputDir) {
    Remove-Item -Path $outputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDir

$page = 1
$pageSize = 500
$issues = @()

do {
    # Construct the API URL - only fetch open issues (excluding RESOLVED and CLOSED)
    $apiUrl = "$sonarCloudUrl/api/issues/search?componentKeys=$projectKey&statuses=OPEN,CONFIRMED,REOPENED&p=$page&ps=$pageSize"

    try {
        # Fetch the issues
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get
        $issues += $response.issues
        $total = $response.total
        $fetchedCount = ($page - 1) * $pageSize + $response.issues.Count
        Write-Host "Fetched page $page. Total issues so far: $($issues.Count)/$total"
        $page++
    }
    catch {
        Write-Error "Error fetching issues from SonarCloud: $_"
        break
    }
} while ($fetchedCount -lt $total)

Write-Host "Successfully fetched $($issues.Count) issues."

# Fetch security hotspots
$page = 1
$pageSize = 500
$hotspots = @()

do {
    # Construct the API URL for hotspots - filter by TO_REVIEW status to exclude remediated/closed hotspots
    $apiUrl = "$sonarCloudUrl/api/hotspots/search?projectKey=$projectKey&statuses=TO_REVIEW&p=$page&ps=$pageSize"

    try {
        # Fetch the hotspots
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get
        $hotspots += $response.hotspots
        $total = $response.paging.total
        $fetchedCount = ($page - 1) * $pageSize + $response.hotspots.Count
        Write-Host "Fetched hotspot page $page. Total hotspots so far: $($hotspots.Count)/$total"
        $page++
    }
    catch {
        Write-Error "Error fetching hotspots from SonarCloud: $_"
        break
    }
} while ($fetchedCount -lt $total)

# Filter out any hotspots with REVIEWED status
$hotspots = $hotspots | Where-Object { $_.status -ne 'REVIEWED' }

Write-Host "Successfully fetched $($hotspots.Count) security hotspots (excluding reviewed/remediated/closed)."

# Create individual markdown files for each issue, organized by severity and category
# Map SonarQube severities to user-friendly categories
$severityMap = @{
    'BLOCKER' = 'Blocker'
    'CRITICAL' = 'High'
    'MAJOR' = 'Medium'
    'MINOR' = 'Low'
    'INFO' = 'Info'
}

# Map SonarQube issue types to categories
$categoryMap = @{
    'VULNERABILITY' = 'Security'
    'BUG' = 'Reliability'
    'CODE_SMELL' = 'Maintainability'
}

foreach ($issue in $issues) {
    $originalSeverity = $issue.severity
    $mappedSeverity = $severityMap[$originalSeverity]
    if (-not $mappedSeverity) {
        $mappedSeverity = $originalSeverity
    }

    $issueType = $issue.type
    $mappedCategory = $categoryMap[$issueType]
    if (-not $mappedCategory) {
        $mappedCategory = $issueType
    }

    $severityDir = Join-Path -Path $outputDir -ChildPath "issues\$mappedSeverity"
    if (-not (Test-Path -Path $severityDir)) {
        New-Item -ItemType Directory -Path $severityDir -Force
    }

    $categoryDir = Join-Path -Path $severityDir -ChildPath $mappedCategory
    if (-not (Test-Path -Path $categoryDir)) {
        New-Item -ItemType Directory -Path $categoryDir -Force
    }

    $issueKey = $issue.key
    $issueFile = Join-Path -Path $categoryDir -ChildPath "$issueKey.md"
    $issueContent = @"
# $($issue.message)

**Severity:** $mappedSeverity
**Category:** $mappedCategory
**Component:** $($issue.component)
**Line:** $($issue.line)
**Status:** $($issue.status)
**Type:** $($issue.type)
**Message:** $($issue.message)
[Link to issue]($($sonarCloudUrl)/project/issues?id=$projectKey&open=$issueKey)
"@
    $issueContent | Out-File -FilePath $issueFile -Encoding utf8
}

Write-Host "Created markdown files for each issue in respective severity and category folders under $outputDir\issues"

# Create individual markdown files for each security hotspot, organized by severity and category
# Map SonarQube hotspot vulnerability probabilities to user-friendly categories
$hotspotSeverityMap = @{
    'HIGH' = 'High'
    'MEDIUM' = 'Medium'
    'LOW' = 'Low'
}

# All security hotspots belong to the Security category
$hotspotCategory = 'Security'

foreach ($hotspot in $hotspots) {
    $originalSeverity = $hotspot.vulnerabilityProbability
    $mappedSeverity = $hotspotSeverityMap[$originalSeverity]
    if (-not $mappedSeverity) {
        $mappedSeverity = $originalSeverity
    }

    $severityDir = Join-Path -Path $outputDir -ChildPath "hotspots\$mappedSeverity"
    if (-not (Test-Path -Path $severityDir)) {
        New-Item -ItemType Directory -Path $severityDir -Force
    }

    $categoryDir = Join-Path -Path $severityDir -ChildPath $hotspotCategory
    if (-not (Test-Path -Path $categoryDir)) {
        New-Item -ItemType Directory -Path $categoryDir -Force
    }

    $hotspotKey = $hotspot.key
    $hotspotFile = Join-Path -Path $categoryDir -ChildPath "$hotspotKey.md"
    $hotspotContent = @"
# $($hotspot.ruleKey)

**Severity:** $mappedSeverity
**Category:** $hotspotCategory
**Component:** $($hotspot.component)
**Line:** $($hotspot.line)
**Status:** $($hotspot.status)
**Rule:** $($hotspot.ruleKey)
**Message:** $($hotspot.message)
[Link to hotspot]($($sonarCloudUrl)/project/security_hotspots?id=$projectKey&hotspots=$hotspotKey)
"@
    $hotspotContent | Out-File -FilePath $hotspotFile -Encoding utf8
}

Write-Host "Created markdown files for each security hotspot in respective severity and category folders under $outputDir\hotspots"

# Fetch duplication metrics for the project
Write-Host "Fetching duplication metrics..."
$apiUrl = "$sonarCloudUrl/api/measures/component?component=$projectKey&metricKeys=duplicated_lines_density,duplicated_lines,duplicated_blocks,duplicated_files"
try {
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get
    $duplicationMetrics = @{}
    foreach ($measure in $response.component.measures) {
        $duplicationMetrics[$measure.metric] = $measure.value
    }
    Write-Host "Duplication Metrics:"
    Write-Host "  - Duplicated Lines Density: $($duplicationMetrics['duplicated_lines_density'])%"
    Write-Host "  - Duplicated Lines: $($duplicationMetrics['duplicated_lines'])"
    Write-Host "  - Duplicated Blocks: $($duplicationMetrics['duplicated_blocks'])"
    Write-Host "  - Duplicated Files: $($duplicationMetrics['duplicated_files'])"
}
catch {
    Write-Error "Error fetching duplication metrics from SonarCloud: $_"
}

# Fetch all files in the project to check for duplications
Write-Host "Fetching project files for duplication analysis..."
$page = 1
$pageSize = 500
$allFiles = @()

do {
    $apiUrl = "$sonarCloudUrl/api/components/tree?component=$projectKey&qualifiers=FIL,UTS&p=$page&ps=$pageSize"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get
        $allFiles += $response.components
        $total = $response.paging.total
        $fetchedCount = ($page - 1) * $pageSize + $response.components.Count
        Write-Host "Fetched file page $page. Total files so far: $($allFiles.Count)/$total"
        $page++
    }
    catch {
        Write-Error "Error fetching files from SonarCloud: $_"
        break
    }
} while ($fetchedCount -lt $total)

Write-Host "Successfully fetched $($allFiles.Count) files."

# Fetch duplications for each file
$duplications = @()
$filesWithDuplications = 0

foreach ($file in $allFiles) {
    $fileKey = $file.key
    $apiUrl = "$sonarCloudUrl/api/duplications/show?key=$fileKey"
    
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get
        if ($response.duplications.Count -gt 0) {
            $filesWithDuplications++
            foreach ($duplication in $response.duplications) {
                $duplicationInfo = [PSCustomObject]@{
                    File = $file.path
                    FileKey = $fileKey
                    StartLine = $duplication._ref.startLine
                    EndLine = $duplication._ref.endLine
                    DuplicatedLines = $duplication._ref.endLine - $duplication._ref.startLine + 1
                    Duplicates = @($duplication.duplicates | ForEach-Object {
                        [PSCustomObject]@{
                            File = if ($response.files.ContainsKey($_._ref)) { $response.files[$_.path] } else { $_.path }
                            StartLine = $_._ref.startLine
                            EndLine = $_._ref.endLine
                        }
                    })
                }
                $duplications += $duplicationInfo
            }
        }
    }
    catch {
        # Keep going with the remaining files, but say which one was skipped and why.
        Write-Warning "Skipped duplications for ${fileKey}: $($_.Exception.Message)"
    }
}

Write-Host "Found duplications in $filesWithDuplications files with $($duplications.Count) total duplication blocks."

# Create markdown files for duplications, organized by file
$duplicationDir = Join-Path -Path $outputDir -ChildPath "duplications"
if (-not (Test-Path -Path $duplicationDir)) {
    New-Item -ItemType Directory -Path $duplicationDir -Force
}

# Create a summary file for duplication metrics
$metricsFile = Join-Path -Path $duplicationDir -ChildPath "duplication_metrics.md"
$metricsContent = @"
# Duplication Metrics for $projectKey

## Overall Metrics

| Metric | Value |
|--------|-------|
| Duplicated Lines Density | $($duplicationMetrics['duplicated_lines_density'])% |
| Duplicated Lines | $($duplicationMetrics['duplicated_lines']) |
| Duplicated Blocks | $($duplicationMetrics['duplicated_blocks']) |
| Duplicated Files | $($duplicationMetrics['duplicated_files']) |

## Files with Duplications

$filesWithDuplications files contain duplicated code blocks.
"@
$metricsContent | Out-File -FilePath $metricsFile -Encoding utf8

# Create individual markdown files for each duplication block, organized by file
$filesProcessed = @{}
foreach ($duplication in $duplications) {
    $fileName = Split-Path -Path $duplication.File -Leaf
    $fileDir = Join-Path -Path $duplicationDir -ChildPath $fileName
    if (-not (Test-Path -Path $fileDir)) {
        New-Item -ItemType Directory -Path $fileDir -Force
    }
    
    $duplicationId = "$($duplication.FileKey)_$($duplication.StartLine)-$($duplication.EndLine)" -replace '[\\/:*?"<>|]', '_'
    $duplicationFile = Join-Path -Path $fileDir -ChildPath "$duplicationId.md"
    
    $duplicateList = ""
    foreach ($dup in $duplication.Duplicates) {
        $duplicateList += "`n- **$($dup.File):** Lines $($dup.StartLine)-$($dup.EndLine)"
    }
    
    $duplicationContent = @"
# Duplicated Code Block

**File:** $($duplication.File)
**Lines:** $($duplication.StartLine)-$($duplication.EndLine)
**Duplicated Lines:** $($duplication.DuplicatedLines)

## Duplicates Found In

$duplicateList

[Link to file duplications]($($sonarCloudUrl)/code/duplications?id=$projectKey&duplicates=$($duplication.FileKey))
"@
    $duplicationContent | Out-File -FilePath $duplicationFile -Encoding utf8
    
    if (-not $filesProcessed.ContainsKey($duplication.File)) {
        $filesProcessed[$duplication.File] = 0
    }
    $filesProcessed[$duplication.File]++
}

Write-Host "Created markdown files for duplications in $outputDir\duplications"
Write-Host "Total: $($issues.Count) open issues, $($hotspots.Count) unreviewed security hotspots, and $($duplications.Count) duplication blocks processed (remediated/closed items excluded)."
