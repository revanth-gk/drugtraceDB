# One-command demo start: local MySQL + schema check + Flask app.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

& (Join-Path $PSScriptRoot 'start_mysql_local.ps1')
python (Join-Path $PSScriptRoot 'init_db.py')
python (Join-Path $PSScriptRoot 'app.py')
