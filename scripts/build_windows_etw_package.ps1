param(
    [string]$PythonExe = "C:\dev\CipherSentry\Prototype-CipherSentry-main\.venv\Scripts\python.exe",
    [string]$OutputBase = "C:\dev\CipherSentry\Experiments"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python interpreter missing."
}

if (-not (Test-Path -LiteralPath $OutputBase -PathType Container)) {
    throw "Output directory missing."
}

$project = Join-Path $repo "etw\LiveEtwStreamer\LiveEtwStreamer.csproj"
$spec = Join-Path $repo "CipherSentry.spec"

foreach ($required in @($project, $spec)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing project file: $required"
    }
}

$output = Join-Path $OutputBase (
    "CipherSentry-Combined-" + (Get-Date -Format "yyyyMMdd-HHmmss")
)

if (Test-Path -LiteralPath $output) {
    throw "Output already exists."
}

$dist = Join-Path $output "dist"
$work = Join-Path $output "build"
$publish = Join-Path $output "etw-publish"

Push-Location $repo
try {
    Write-Host "=== BUILD PYTHON GUI ==="

    & $PythonExe -m PyInstaller --noconfirm `
        --distpath $dist --workpath $work $spec

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed."
    }

    Write-Host "=== PUBLISH ETW COLLECTOR ==="

    dotnet publish $project -c Release -r win-x64 `
        --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $publish

    if ($LASTEXITCODE -ne 0) {
        throw ".NET publish failed."
    }

    $bundle = Join-Path $dist "CipherSentry"
    $gui = Join-Path $bundle "CipherSentry.exe"
    $source = Join-Path $publish "LiveEtwStreamer.exe"
    $sidecarDir = Join-Path $bundle "etw"
    $target = Join-Path $sidecarDir "LiveEtwStreamer.exe"

    foreach ($required in @($gui, $source)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Missing built executable: $required"
        }
    }

    New-Item -ItemType Directory -Path $sidecarDir -Force |
        Out-Null

    Copy-Item -LiteralPath $source -Destination $target `
        -ErrorAction Stop

    Write-Host "=== VERIFY SIDECAR INTEGRITY ==="

    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    if ($sourceHash -ne $targetHash) {
        throw "Sidecar SHA-256 mismatch."
    }

    Write-Host "Integrity: PASS"

    Write-Host "=== RUN SYNTHETIC SELF-TEST ==="

    $stdout = Join-Path $output "selftest.jsonl"
    $stderr = Join-Path $output "selftest-stderr.txt"

    $test = Start-Process -FilePath $target `
        -ArgumentList "--self-test" `
        -Wait -PassThru `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr

    if ($test.ExitCode -ne 0) {
        throw "Sidecar self-test failed. Check: $stderr"
    }

    $records = @(
        Get-Content -LiteralPath $stdout |
            Where-Object { $_.Trim() } |
            ForEach-Object { $_ | ConvertFrom-Json }
    )

    if ($records.Count -ne 2) {
        throw "Unexpected synthetic record count."
    }

    foreach ($record in $records) {
        if ($record.schema -ne 1 -or $record.kind -ne "Write") {
            throw "Invalid synthetic ETW record."
        }
    }

    Write-Host "=== COMBINED PACKAGE BUILD PASSED ==="
    Write-Host "Distribution: $bundle"
    Write-Host "GUI: $gui"
    Write-Host "ETW collector: $target"
    Write-Host "Synthetic records: $($records.Count)"
}
finally {
    Pop-Location
}
