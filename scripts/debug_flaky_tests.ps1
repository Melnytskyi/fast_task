Set-Location -Path "$PSScriptRoot/../out/build/Win-Test/"
$logFile = "$PSScriptRoot/../out/build/Win-Test/test_hunt_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$maxConcurrentJobs = 8
$testExecutables = Get-ChildItem -Path ".\tests\*\Debug\*.exe" 

# Initialize the log file
Set-Content -Path $logFile -Value "--- Test Hunt Started $(Get-Date) ---`n" -Encoding utf8

$cdbPath = (Get-Command "cdb.exe" -ErrorAction SilentlyContinue).Source
if (-not $cdbPath) {
    $cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
}

# Setup the queues
$pendingTests = [System.Collections.ArrayList]::new()
$pendingTests.AddRange($testExecutables)
$activeJobs = @()

$totalCount = $testExecutables.Count
$completedCount = 0

Write-Host "Found $totalCount executables. Starting hunt with max $maxConcurrentJobs parallel jobs..." -ForegroundColor Yellow

# The Dispatcher Loop
while ($pendingTests.Count -gt 0 -or $activeJobs.Count -gt 0) {
    
    # 1. Process and save any jobs that have finished. 
    # Wrapped in @() to prevent single-item unrolling bug
    $completedJobs = @($activeJobs | Where-Object { $_.State -ne 'Running' })
    
    foreach ($job in $completedJobs) {
        # Receive the output and immediately append it to the file
        $output = Receive-Job -Job $job
        $output | Out-File -FilePath $logFile -Append -Encoding utf8
        
        # Update progress in the console
        $completedCount++
        Write-Host "[$completedCount/$totalCount] Finished: $($job.Name)" -ForegroundColor Green
        
        # Clear the completed job to free up memory
        Remove-Job -Job $job
    }
    
    # Update our active list to only include actually running jobs.
    # Wrapped in @() to prevent single-item unrolling bug
    $activeJobs = @($activeJobs | Where-Object { $_.State -eq 'Running' })
    
    # 2. Fill empty slots with new tests
    while ($activeJobs.Count -lt $maxConcurrentJobs -and $pendingTests.Count -gt 0) {
        $exe = $pendingTests[0]
        $pendingTests.RemoveAt(0)
        
        Write-Host "Starting: $($exe.Name)..." -ForegroundColor DarkGray
        
        $job = Start-Job -Name $exe.Name -ScriptBlock {
            param($testPath, $cdbExePath)
            
            $jobOutput = @("`n=======================================================")
            $jobOutput += "--- Starting hunt for: $testPath ---"
            
            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()
            $hung = $false
            
            for ($attempt = 1; $attempt -le 200; $attempt++) {
                $process = Start-Process -FilePath $testPath -ArgumentList "--gtest_catch_exceptions=0", "-halt_on_exception" -PassThru -WindowStyle Hidden -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                $timeoutMs = 4000
                $exitedCleanly = $process.WaitForExit($timeoutMs)
                
                if (-not $exitedCleanly) {
                    $hung = $true
                    $jobOutput += "=== HANG at attempt $attempt ==="
                    
                    $jobOutput += "`n--- Test Console Output (STDOUT) ---"
                    $jobOutput += Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
                    
                    $jobOutput += "`n--- Test Console Error (STDERR) ---"
                    $jobOutput += Get-Content $tempErr -Raw -ErrorAction SilentlyContinue
                    
                    if (Test-Path $cdbExePath) {
                        $jobOutput += "`n--- CDB Scheduler values and Stack Trace ---"
                        $cdbTrace = (& $cdbExePath -p $process.Id -c "~*k; dx fast_task::glob; q" 2>&1) | Out-String
                        $jobOutput += $cdbTrace
                    } else {
                        $jobOutput += "`n[ERROR] cdb.exe not found at $cdbExePath."
                    }
                    
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
                    
                    $jobOutput += "=== END HANG DATA ==="
                    break 
                }elseif ($process.ExitCode -ne 0) {
                    $hung = $true # Reuse the flag to break the 200-attempt loop
                    
                    $jobOutput += "=== FAST CRASH at attempt $attempt ==="
                    $jobOutput += "Exit Code: $($process.ExitCode)"
                    
                    $jobOutput += "`n--- Test Console Output (STDOUT) ---"
                    $jobOutput += $stdoutContent
                    
                    $jobOutput += "`n--- Test Console Error (STDERR) ---"
                    $jobOutput += $stderrContent
                    
                    $jobOutput += "`n[INFO] Process exited immediately; no live CDB trace can be captured."
                    $jobOutput += "=== END CRASH DATA ==="
                    break
                }
            }
            
            Remove-Item $tempOut, $tempErr -ErrorAction SilentlyContinue
            
            if (-not $hung) {
                $jobOutput += "Result: COMPLETED 200 ATTEMPTS WITHOUT HANGING"
            }
            $jobOutput += "--- Finished hunt for: $testPath ---"
            
            return $jobOutput -join "`n"
            
        } -ArgumentList $exe.FullName, $cdbPath 
        
        $activeJobs += $job
    }
    
    # Pause the loop briefly to prevent it from eating 100% of your CPU while checking statuses
    Start-Sleep -Milliseconds 250
}

Write-Host "`nHunt completely finished. All results are saved to $logFile" -ForegroundColor Cyan