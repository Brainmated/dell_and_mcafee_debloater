
<# 
Remove-UndesiredApps.ps1
Purpose : Removes OEM McAfee/Dell apps & services with analytical CLI logging
Author  : ASK
Exit    : 0 = success, 1 = partial failures, 2 = fatal error
#>

[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [switch]$EnableTranscript,
    [switch]$Quiet,
    [string]$LogDirectory = "C:\ProgramData\IntuneRemediation",
    [string]$LogName = "DellMcAfeeCleanup.log",
    [int]$MaxLogFiles = 5,
    [int]$MaxLogSizeMB = 10,
    [switch]$RunMCPR,
    [string]$MCPRPath = "",
    [string]$MCPRUrl = ""
)

if ([string]::IsNullOrWhiteSpace($MCPRPath)) {
    $MCPRPath = Join-Path -Path $PSScriptRoot -ChildPath "MCPR.exe"
}

$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Patterns (same as yours) ---
$Patterns = @(
    "McAfee",
    "WebAdvisor*",
    "WebAdvisor από την McAfee*",
    "McAfee WPS*",
    "Dell Core Services",
    "Dell Optimizer",
    "Dell SupportAssist",
    "Dell SupportAssist Remediation",
    "Dell SupportAssist OS Recovery Plugin*",
    "Dell.SupportAssistforPCs",
    "Dell Update*",
    "Dell Command*Update*",
    "Dell SupportAssist OS Recovery*",
    "SupportAssist OS Recovery*"
)

# --- Utilities ---
function Ensure-Dir { param([string]$Path) if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
function NameLike { param([string]$s,[string[]]$pats) foreach ($p in $pats) { if ($s -like $p) { return $true } } return $false }

$LogFile = Join-Path $LogDirectory $LogName
Ensure-Dir $LogDirectory

function Rotate-Log { param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $sizeMB = [math]::Round((Get-Item $FilePath).Length/1MB,2)
        if ($sizeMB -ge $MaxLogSizeMB) {
            for ($i=$MaxLogFiles; $i -ge 1; $i--) {
                $src = "{0}.{1}" -f $FilePath, $i
                $dst = "{0}.{1}" -f $FilePath, ($i+1)
                if (Test-Path $src) { Move-Item -Path $src -Destination $dst -Force }
            }
            Move-Item -Path $FilePath -Destination "$FilePath.1" -Force
        }
    } catch { }
}

Rotate-Log -FilePath $LogFile

function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string]$Level = 'INFO',
        [string]$Message,
        [string]$Component = 'Cleanup',
        [string]$Target = '',
        [int]$EventId = 1000
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[{0}] [{1}] [{2}] {3}{4}" -f $ts, $Level, $Component, $Message, ($(if ($Target) { " (Target: $Target)" } else { "" }))
    if (-not $Quiet) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
            default { Write-Host $line }
        }
    }
    try { $line | Out-File -FilePath $LogFile -Append -Encoding UTF8 } catch { }
}

# Optional transcript
if ($EnableTranscript) {
    try { Start-Transcript -Path (Join-Path $LogDirectory "Transcript_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt") -NoClobber | Out-Null; Write-Log -Message "Transcript started." } catch {}
}

$global:Removed = New-Object System.Collections.Generic.List[string]
$global:Failed  = New-Object System.Collections.Generic.List[string]

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log -Message "==== Remediation start ===="

# ------------------------------
# Step 0: Stop services & processes
# ------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log -Message "Step 0: Stop services & processes" -Component "Step0"

$svcNames = @('DellClientManagementService','DellDataVault','SupportAssistAgent','SupportAssist','DellOSRecovery',
              'McAfeeFramework','McAfeeWebAdvisor','McAfeeWPS')

foreach ($s in $svcNames) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log -Message "Stopping/Disabling service" -Target $s -Component "Services"
        try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue; $Removed.Add("Service:$s") }
        catch { $Failed.Add("Service:$s"); Write-Log -Level WARN -Message "Failed to stop/disable: $($_.Exception.Message)" -Target $s -Component "Services" }
    } else { Write-Log -Level DEBUG -Message "Service not present" -Target $s -Component "Services" }
}

Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'SupportAssist|Dell|McAfee|WebAdvisor' } | ForEach-Object {
    Write-Log -Level DEBUG -Message "Killing process" -Target $_.ProcessName -Component "Processes"
    try { $_.Kill(); $Removed.Add("Process:$($_.ProcessName)") } catch { $Failed.Add("Process:$($_.ProcessName)") }
}
Write-Log -Level INFO -Message ("Step 0 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step0"

# ------------------------------
# Step 1: Remove Appx (all users)
# ------------------------------
$sw.Restart()
Write-Log -Message "Step 1: Remove Appx packages (AllUsers)" -Component "Step1"

Get-AppxPackage -AllUsers | ForEach-Object {
    if (NameLike $_.Name $Patterns -or NameLike $_.PackageFamilyName $Patterns) {
        Write-Log -Message "Removing Appx" -Target $_.Name -Component "Appx"
        try {
            if ($PSCmdlet.ShouldProcess($_.Name, "Remove-AppxPackage")) {
                Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                $Removed.Add("Appx:$($_.Name)")
            }
        } catch { $Failed.Add("Appx:$($_.Name)"); Write-Log -Level ERROR -Message "Appx removal failed: $($_.Exception.Message)" -Target $_.Name -Component "Appx" }
    }
}
Write-Log -Level INFO -Message ("Step 1 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step1"

# ------------------------------
# Step 2: Registry uninstall (Win32)
# ------------------------------
$sw.Restart()
Write-Log -Message "Step 2: Uninstall via registry (Win32)" -Component "Step2"

$roots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)

foreach ($root in $roots) {
    if (-not (Test-Path $root)) { Write-Log -Level DEBUG -Message "Uninstall root not found" -Target $root -Component "Win32"; continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $dn = $props.DisplayName
        $quiet = $props.UninstallString
        if ($dn -and (NameLike $dn $Patterns) -and $quiet) {
            $cmd = $quiet.Trim()
            if ($cmd -match 'msiexec') {
                if ($cmd -notmatch '/quiet') { $cmd += ' /quiet' }
                if ($cmd -notmatch '/qn')    { $cmd += ' /qn' }
            } else {
                if ($cmd -notmatch '/quiet|/silent|/s') { $cmd += ' /quiet' }
            }
            Write-Log -Message "Uninstalling via registry" -Target $dn -Component "Win32"
            try {
                $pi = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -WindowStyle Hidden -PassThru
                Write-Log -Level DEBUG -Message ("Process exit code: {0}" -f $pi.ExitCode) -Target $dn -Component "Win32"
                if ($pi.ExitCode -eq 0) { $Removed.Add("Win32:$dn") }
                else { $Failed.Add("Win32:$dn"); Write-Log -Level WARN -Message "Non-zero exit code ($($pi.ExitCode))" -Target $dn -Component "Win32" }
            } catch {
                $Failed.Add("Win32:$dn"); Write-Log -Level ERROR -Message "Uninstall failed: $($_.Exception.Message)" -Target $dn -Component "Win32"
            }
        }
    }
}
Write-Log -Level INFO -Message ("Step 2 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step2"


function Invoke-Mcpr {
    param(
        [string]$Path,
        [string]$Url,
        [switch]$ForceReboot
    )

    $component = "MCPR"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Message "MCPR step requested." -Component $component

    # Resolve executable path
    $mcprExe = $null
    $tempDir = Join-Path $env:TEMP "MCPR"
    Ensure-Dir $tempDir

    if ([string]::IsNullOrWhiteSpace($Path) -and [string]::IsNullOrWhiteSpace($Url)) {
        Write-Log -Level WARN -Message "No MCPRPath or MCPRUrl provided; skipping MCPR." -Component $component
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (Test-Path $Path) { $mcprExe = (Resolve-Path $Path).Path }
        else {
            Write-Log -Level WARN -Message "MCPRPath not found: $Path" -Component $component
        }
    }

    if (-not $mcprExe -and -not [string]::IsNullOrWhiteSpace($Url)) {
        try {
            $fileName = Split-Path $Url -Leaf
            if ([string]::IsNullOrWhiteSpace($fileName)) { $fileName = "MCPR.exe" }
            $dlPath = Join-Path $tempDir $fileName
            Write-Log -Message "Downloading MCPR..." -Target $Url -Component $component
            # Use Invoke-WebRequest for simplicity (BITS if you prefer)
            Invoke-WebRequest -Uri $Url -OutFile $dlPath -UseBasicParsing -ErrorAction Stop
            $mcprExe = $dlPath
            Write-Log -Message "Downloaded MCPR to $dlPath" -Component $component
        } catch {
            Write-Log -Level ERROR -Message "Failed to download MCPR: $($_.Exception.Message)" -Component $component
            $Failed.Add("MCPR:Download")
            return
        }
    }

    if (-not $mcprExe -or -not (Test-Path $mcprExe)) {
        Write-Log -Level WARN -Message "MCPR executable not available; skipping." -Component $component
        return
    }

    # Arguments: MCPR supports silent modes on many builds. We try quiet first; if it fails, we rerun interactively disabled (still logs).
    # Common flags seen in the field: /q or /silent. We'll prefer /q.
    $args = "/q"
    Write-Log -Message "Executing MCPR" -Target $mcprExe -Component $component
    Write-Log -Level DEBUG -Message ("Args: {0}" -f $args) -Component $component

    try {
        $proc = Start-Process -FilePath $mcprExe -ArgumentList $args -Wait -WindowStyle Hidden -PassThru
        Write-Log -Level DEBUG -Message ("MCPR exit code: {0}" -f $proc.ExitCode) -Component $component

        switch ($proc.ExitCode) {
            0 { Write-Log -Message "MCPR completed successfully." -Component $component; $Removed.Add("MCPR:Success") }
            default {
                Write-Log -Level WARN -Message ("MCPR returned non-zero exit code: {0}" -f $proc.ExitCode) -Component $component
                $Failed.Add("MCPR:ExitCode:$($proc.ExitCode)")
            }
        }
    } catch {
        Write-Log -Level ERROR -Message "MCPR execution failed: $($_.Exception.Message)" -Component $component
        $Failed.Add("MCPR:Exception")
        return
    } finally {
        $sw.Stop()
        Write-Log -Message ("MCPR elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component $component
    }

    # Try to surface MCPR logs if present (best-effort; paths vary by version)
    $logHints = @(
        "C:\Windows\Temp\McAfeeLogs",
        "C:\ProgramData\McAfee\Logs",
        (Join-Path $env:TEMP "McAfeeLogs"),
        (Join-Path $env:TEMP "MCPRLogs")
    )
    foreach ($lp in $logHints) {
        if (Test-Path $lp) {
            Write-Log -Level DEBUG -Message ("MCPR logs folder detected: {0}" -f $lp) -Component $component
        }
    }

    if ($ForceReboot) {
        Write-Log -Level WARN -Message "Forcing reboot due to MCPR request." -Component $component
        # Return a specific exit to allow Intune/runner to reboot, or reboot here:
        try { shutdown.exe /r /t 5 /c "Reboot required after MCPR cleanup" } catch {}
    } else {
        Write-Log -Level INFO -Message "Reboot recommended after MCPR. Schedule or prompt user as needed." -Component $component
    }
}


# ------------------------------
# Step 3: Winget uninstall
# ------------------------------
$sw.Restart()
Write-Log -Message "Step 3: Winget uninstall (best effort)" -Component "Step3"

function Try-WingetRemove {
    param([string]$Query)
    try {
        $list = winget list --source winget --accept-source-agreements --disable-interactivity --name "$Query" 2>$null
        Write-Log -Level DEBUG -Message "winget list exit: $LASTEXITCODE" -Target $Query -Component "Winget"
        if ($LASTEXITCODE -eq 0 -and ($list | Select-String -SimpleMatch "$Query")) {
            Write-Log -Message "Winget uninstall" -Target $Query -Component "Winget"
            $u = winget uninstall --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --name "$Query"
            Write-Log -Level DEBUG -Message "winget uninstall exit: $LASTEXITCODE" -Target $Query -Component "Winget"
            if ($LASTEXITCODE -eq 0) { $Removed.Add("Winget:$Query") }
            else { $Failed.Add("Winget:$Query"); Write-Log -Level WARN -Message "Winget non-zero exit: $LASTEXITCODE" -Target $Query -Component "Winget" }
        } else {
            Write-Log -Level DEBUG -Message "No winget match for query" -Target $Query -Component "Winget"
        }
    } catch {
        $Failed.Add("Winget:$Query"); Write-Log -Level ERROR -Message "Winget error: $($_.Exception.Message)" -Target $Query -Component "Winget"
    }
}

$wingetTargets = @('Dell SupportAssist','SupportAssist','Dell Update','Dell Command Update','Dell Optimizer',
                   'McAfee WebAdvisor','WebAdvisor','McAfee WPS')
foreach ($q in $wingetTargets) { Try-WingetRemove -Query $q }
Write-Log -Level INFO -Message ("Step 3 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step3"

# ------------------------------
# Step 4: Scheduled tasks cleanup
# ------------------------------
$sw.Restart()
Write-Log -Message "Step 4: Remove scheduled tasks" -Component "Step4"

Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -match 'Dell|SupportAssist|Optimizer|Command.*Update|OS.*Recovery|McAfee|WebAdvisor'
} | ForEach-Object {
    Write-Log -Message "Removing scheduled task" -Target $_.TaskName -Component "Tasks"
    try { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false; $Removed.Add("Task:$($_.TaskName)") }
    catch { $Failed.Add("Task:$($_.TaskName)"); Write-Log -Level WARN -Message "Task removal failed: $($_.Exception.Message)" -Target $_.TaskName -Component "Tasks" }
}
Write-Log -Level INFO -Message ("Step 4 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step4"

# ------------------------------
# Step 5: File system cleanup
# ------------------------------
$sw.Restart()
Write-Log -Message "Step 5: File system cleanup" -Component "Step5"

$paths = @('C:\Program Files\Dell','C:\Program Files (x86)\Dell',
           'C:\ProgramData\Dell','C:\ProgramData\McAfee','C:\Program Files\McAfee','C:\Program Files (x86)\McAfee')
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Log -Message "Removing directory tree" -Target $p -Component "FS"
        try { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; $Removed.Add("Path:$p") }
        catch { $Failed.Add("Path:$p"); Write-Log -Level WARN -Message "Directory removal failed: $($_.Exception.Message)" -Target $p -Component "FS" }
    } else { Write-Log -Level DEBUG -Message "Path not present" -Target $p -Component "FS" }
}
Write-Log -Level INFO -Message ("Step 5 elapsed: {0} ms" -f $sw.ElapsedMilliseconds) -Component "Step5"


# ------------------------------
# Step 6: MCPR (optional)
# ------------------------------
if ($RunMCPR) {
    Write-Log -Message "Step 6: Running MCPR (McAfee Consumer Product Removal)" -Component "Step6"
    Invoke-Mcpr -Path $MCPRPath -Url $MCPRUrl -ForceReboot:$ForceRebootAfterMCPR
} else {
    Write-Log -Level DEBUG -Message "MCPR step disabled. Skipping." -Component "Step6"
}

# ------------------------------
# Summary & exit
# ------------------------------
$swTotal.Stop()
Write-Log -Message ("Removed items count: {0}" -f $Removed.Count) -Component "Summary"
if ($Removed.Count) {
    Write-Log -Level DEBUG -Message ("Removed:`n" + ($Removed | Sort-Object | Out-String)) -Component "Summary"
}

if ($Failed.Count) {
    Write-Log -Level WARN -Message ("Failures count: {0}" -f $Failed.Count) -Component "Summary"
    Write-Log -Level WARN -Message ("Failed:`n" + ($Failed | Sort-Object | Out-String)) -Component "Summary"
}

Write-Log -Message ("Total elapsed: {0} ms" -f $swTotal.ElapsedMilliseconds) -Component "Summary"
Write-Log -Message "==== Remediation end ===="

if ($EnableTranscript) {
    try { Stop-Transcript | Out-Null } catch {}
}

# Decide exit code based on failures captured above
try {
    if ($Failed.Count -gt 0) {
        Write-Log -Level WARN -Message "Exiting with non-zero code due to failures."
        exit 1
    } else {
        Write-Log -Level INFO -Message "Exiting with success (no failures)."
        exit 0
    }
}
catch {
    # Defensive catch to ensure we always exit predictably and log the reason
    Write-Log -Level ERROR -Message ("Unexpected termination: {0}" -f $_.Exception.Message) -Component "Exit"
    try { if ($EnableTranscript) { Stop-Transcript | Out-Null } } catch {}
    exit 2
}

