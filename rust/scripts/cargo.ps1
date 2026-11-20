param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArguments = @('build', '--workspace')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$cargoPath = Join-Path $env:USERPROFILE '.cargo\bin'
$oldPath = $env:PATH
$oldDlltool = $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_DLLTOOL
$oldLinker = $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER
$oldRustflags = $env:RUSTFLAGS
$exitCode = 1

function Get-MingwBin {
    param([string]$Configured)

    $candidates = @()
    if ($Configured) { $candidates += $Configured }
    $candidates += @(
        (Join-Path $env:TEMP 'w64devkit-dl\extracted\w64devkit\bin'),
        'C:\w64devkit\bin',
        'D:\Tools\w64devkit\bin'
    )
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $complete = $true
        foreach ($tool in @('gcc.exe', 'as.exe', 'dlltool.exe')) {
            if (-not (Test-Path (Join-Path $candidate $tool))) { $complete = $false; break }
        }
        if ($complete) { return $candidate }
    }
    return $null
}

try {
    $env:PATH = "$cargoPath;$env:PATH"

    $target = (& rustc -vV | Select-String '^host:' | ForEach-Object { $_.ToString().Split(':')[1].Trim() })
    if ($LASTEXITCODE -ne 0) { throw 'Rust is unavailable. Check rustup show.' }

    # Only GNU targets need an external MinGW toolchain; MSVC targets keep defaults.
    if ($target -like '*windows-gnu') {
        $mingwBin = Get-MingwBin -Configured $env:NPS_MINGW_BIN
        if (-not $mingwBin) {
            throw 'A complete MinGW-w64 toolchain is required (gcc.exe, as.exe, dlltool.exe). Set NPS_MINGW_BIN to its bin directory, or install w64devkit.'
        }
        $env:PATH = "$mingwBin;$env:PATH"
        # Rust's bundled self-contained linker cannot run dlltool here, so use the real toolchain.
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $mingwBin 'gcc.exe'
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_DLLTOOL = Join-Path $mingwBin 'dlltool.exe'
        Remove-Item Env:\RUSTFLAGS -ErrorAction SilentlyContinue
        Write-Verbose "Using MinGW toolchain: $mingwBin"
    }

    Push-Location $projectRoot
    try {
        & cargo @CargoArguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:PATH = $oldPath
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_DLLTOOL = $oldDlltool
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $oldLinker
    $env:RUSTFLAGS = $oldRustflags
}

exit $exitCode