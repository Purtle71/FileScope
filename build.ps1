[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$SourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildRoot = Join-Path $env:TEMP ("FileScopeBuild_" + [Guid]::NewGuid().ToString('N'))
$VenvRoot = Join-Path $BuildRoot 'venv'
$DistRoot = Join-Path $BuildRoot 'dist'
$WorkRoot = Join-Path $BuildRoot 'pyinstaller'
$LogPath = Join-Path $BuildRoot 'build.log'
$PublishRoot = Join-Path $SourceRoot 'dist'
$OutputPath = Join-Path $PublishRoot 'FileScope.exe'
$FailureLog = Join-Path $SourceRoot 'FileScope_build_error.txt'
$TranscriptStarted = $false

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Write-Step $Label
    $LASTEXITCODE = 0
    & $Action
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode."
    }
}

function Find-Python314 {
    $candidates = @()
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        $candidates += [pscustomobject]@{ Command = 'py.exe'; Prefix = @('-3.14') }
    }
    foreach ($path in @(
        (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.14-64\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314\python.exe'),
        (Join-Path $env:ProgramFiles 'Python314\python.exe')
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $candidates += [pscustomobject]@{ Command = $path; Prefix = @() }
        }
    }
    if (Get-Command python.exe -ErrorAction SilentlyContinue) {
        $candidates += [pscustomobject]@{ Command = 'python.exe'; Prefix = @() }
    }

    $probeCode = "import struct,sys; print(str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'|'+str(struct.calcsize('P')*8)+'|'+sys.executable)"
    foreach ($candidate in $candidates) {
        try {
            $arguments = @($candidate.Prefix) + @('-c', $probeCode)
            $probe = & ([string]$candidate.Command) @arguments 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $probe) { continue }
            $parts = (($probe | Select-Object -Last 1).ToString().Trim()).Split('|')
            if ($parts.Count -ge 3 -and $parts[0] -eq '3.14' -and $parts[1] -eq '64') {
                return [pscustomobject]@{
                    Command = [string]$candidate.Command
                    Prefix = [string[]]$candidate.Prefix
                    Executable = [string]$parts[2]
                }
            }
        }
        catch { continue }
    }
    return $null
}

function Test-PortableExecutableHeader {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        return ($stream.ReadByte() -eq 0x4D -and $stream.ReadByte() -eq 0x5A)
    }
    finally {
        $stream.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Force -Path $BuildRoot, $PublishRoot | Out-Null
    if (Test-Path -LiteralPath $FailureLog) { Remove-Item -LiteralPath $FailureLog -Force }
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }

    try {
        Start-Transcript -Path $LogPath -Force | Out-Null
        $TranscriptStarted = $true
    }
    catch {
        Write-Warning 'Build transcript logging could not be started.'
    }

    Write-Host 'FileScope single-executable builder' -ForegroundColor White
    Write-Host 'Only precompiled Python wheels are accepted.'

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'FileScope requires 64-bit Windows 10 or Windows 11.'
    }
    foreach ($required in @('app.py', 'FileScope.spec', 'requirements.txt', 'requirements-build.txt')) {
        if (-not (Test-Path -LiteralPath (Join-Path $SourceRoot $required) -PathType Leaf)) {
            throw "Required file is missing: $required"
        }
    }

    Write-Step 'Locating 64-bit Python 3.14'
    $Python = Find-Python314
    if (-not $Python) {
        throw 'Python 3.14 x64 was not found. Install it and run BUILD_FILESCOPE.bat again.'
    }
    Write-Host "Using: $($Python.Executable)"

    Invoke-Checked 'Creating the isolated build environment' {
        $arguments = @($Python.Prefix) + @('-m', 'venv', $VenvRoot)
        & ([string]$Python.Command) @arguments
    }
    $VenvPython = Join-Path $VenvRoot 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        throw 'The Python virtual environment was not created correctly.'
    }

    Invoke-Checked 'Installing pinned precompiled dependencies' {
        & $VenvPython -m pip install --disable-pip-version-check '--only-binary=:all:' --no-deps -r (Join-Path $SourceRoot 'requirements.txt') -r (Join-Path $SourceRoot 'requirements-build.txt')
    }

    $ImportCheck = Join-Path $BuildRoot 'verify_imports.py'
    @'
import importlib.metadata as metadata
import struct
from PySide6.QtCore import qVersion
from PIL import Image
import pefile
import pypdf
import yara_x
import cryptography
import lxml.etree
import loguru
import win32_setctime
from androguard.core.axml import AXMLPrinter
from androguard.core.dex import DEX
import apkInspector
import asn1crypto
import colorama
import cffi
import mutf8

expected_versions = {
    "PySide6-Essentials": "6.11.1",
    "shiboken6": "6.11.1",
    "Pillow": "12.3.0",
    "pefile": "2024.8.26",
    "pypdf": "6.14.2",
    "androguard": "4.1.4",
    "apkInspector": "1.3.6",
    "asn1crypto": "1.5.1",
    "colorama": "0.4.6",
    "cryptography": "49.0.0",
    "cffi": "2.1.0",
    "pycparser": "3.0",
    "loguru": "0.7.3",
    "win32-setctime": "1.2.0",
    "lxml": "6.1.1",
    "mutf8": "1.1.0",
    "yara-x": "1.19.0",
    "pyinstaller": "6.21.0",
    "pyinstaller-hooks-contrib": "2026.6",
    "altgraph": "0.17.5",
    "packaging": "26.2",
    "pywin32-ctypes": "0.2.3",
    "setuptools": "83.0.0",
}
for package, expected in expected_versions.items():
    actual = metadata.version(package)
    if actual != expected:
        raise RuntimeError(f"Unexpected {package} version: {actual} (expected {expected})")
assert struct.calcsize("P") * 8 == 64
assert qVersion() == "6.11.1"
assert win32_setctime.__version__ == "1.2.0"
assert hasattr(loguru, "logger")
print("Dependency imports and versions verified")
'@ | Set-Content -LiteralPath $ImportCheck -Encoding UTF8

    Invoke-Checked 'Verifying native and parser imports' {
        & $VenvPython $ImportCheck
    }

    Invoke-Checked 'Compiling the Python source' {
        & $VenvPython -m compileall -q $SourceRoot
    }

    $env:QT_QPA_PLATFORM = 'offscreen'
    Invoke-Checked 'Running the regression suite' {
        Push-Location $SourceRoot
        try { & $VenvPython -m unittest discover -s tests -v }
        finally { Pop-Location }
    }

    Invoke-Checked 'Running the source self-test' {
        & $VenvPython (Join-Path $SourceRoot 'app.py') --self-test
    }

    Invoke-Checked 'Building FileScope.exe' {
        Push-Location $SourceRoot
        try {
            & $VenvPython -m PyInstaller --noconfirm --clean --distpath $DistRoot --workpath $WorkRoot (Join-Path $SourceRoot 'FileScope.spec')
        }
        finally { Pop-Location }
    }

    $BuiltExe = Join-Path $DistRoot 'FileScope.exe'
    if (-not (Test-Path -LiteralPath $BuiltExe -PathType Leaf)) {
        throw 'PyInstaller did not produce FileScope.exe.'
    }
    if ((Get-Item -LiteralPath $BuiltExe).Length -lt (20 * 1024 * 1024)) {
        throw 'The generated executable is unexpectedly small.'
    }
    if (-not (Test-PortableExecutableHeader -Path $BuiltExe)) {
        throw 'The generated file does not have a Windows PE header.'
    }

    Invoke-Checked 'Running the packaged self-test' {
        & $BuiltExe --self-test
    }

    Copy-Item -LiteralPath $BuiltExe -Destination $OutputPath -Force
    $Hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    $SizeMB = [Math]::Round((Get-Item -LiteralPath $OutputPath).Length / (1024 * 1024), 1)

    Write-Host ''
    Write-Host 'BUILD SUCCESSFUL' -ForegroundColor Green
    Write-Host "Output: $OutputPath"
    Write-Host "Size:   $SizeMB MB"
    Write-Host "SHA256: $Hash"

    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        $TranscriptStarted = $false
    }
    exit 0
}
catch {
    $message = $_.Exception.Message
    Write-Host ''
    Write-Host 'BUILD FAILED' -ForegroundColor Red
    Write-Host $message -ForegroundColor Red

    if ($TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
        $TranscriptStarted = $false
    }

    try {
        $logText = if (Test-Path -LiteralPath $LogPath) { Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue } else { '' }
        @(
            "FileScope build failed: $message",
            "Date: $(Get-Date -Format o)",
            '',
            'Build log:',
            $logText
        ) -join [Environment]::NewLine | Set-Content -LiteralPath $FailureLog -Encoding UTF8
        Write-Host "Details were saved to: $FailureLog"
    }
    catch {}
    exit 1
}
finally {
    try { if ($TranscriptStarted) { Stop-Transcript | Out-Null } } catch {}
    try { if (Test-Path -LiteralPath $BuildRoot) { Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}
