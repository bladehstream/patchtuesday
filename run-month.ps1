[CmdletBinding()]
param(
    [Parameter(Position=0)][string]$Month = (Get-Date).ToString('yyyy-MMM', [cultureinfo]::InvariantCulture),
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$RunnerArguments
)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) { throw 'Install Python 3.11 or later and put python on PATH.' }
$pythonPath = $pythonCommand.Source
$standardPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
$monthlyPython = Join-Path $projectRoot 'work/monthly-venv/Scripts/python.exe'
if (Test-Path -LiteralPath $standardPython) {
    $pythonPath = $standardPython
} elseif (Test-Path -LiteralPath $monthlyPython) {
    $pythonPath = $monthlyPython
} elseif ($RunnerArguments -notcontains '--plan') {
    & $pythonPath -m venv (Join-Path $projectRoot 'work/monthly-venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
    $pythonPath = $monthlyPython
}
if ($RunnerArguments -notcontains '--plan') {
    & $pythonPath -c "import importlib.metadata,sys; sys.exit(importlib.metadata.version('jsonschema') != '4.26.0')" 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $pythonPath -m pip install -r (Join-Path $projectRoot 'requirements-monthly.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Monthly dependencies could not be installed.' }
    }
}
& $pythonPath (Join-Path $projectRoot 'scripts/run_month.py') $Month @RunnerArguments
exit $LASTEXITCODE
