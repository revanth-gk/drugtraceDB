# Starts the project-local MySQL instance used by the prototype.
# It runs on 127.0.0.1:3307 as the current Windows user, so it needs no
# administrator rights and does not touch the installed MySQL80 service.

$ErrorActionPreference = 'Stop'
$mysqlHome = 'C:\Program Files\MySQL\MySQL Server 8.0'
$dataDir = Join-Path $PSScriptRoot 'data\mysql-data'
$logFile = Join-Path $PSScriptRoot 'data\mysql-local.log'
$port = 3307

function Test-Port {
    param([int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(500)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

if (Test-Port $port) {
    Write-Host "MySQL already listening on 127.0.0.1:$port"
    exit 0
}

if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    Write-Host 'Initialising a fresh MySQL data directory...'
    & (Join-Path $mysqlHome 'bin\mysqld.exe') `
        --no-defaults --initialize-insecure `
        "--basedir=$mysqlHome" "--datadir=$dataDir"
}

Write-Host "Starting MySQL on 127.0.0.1:$port (logs: $logFile)"
$argList = @(
    '--no-defaults',
    "`"--basedir=$mysqlHome`"",
    "`"--datadir=$dataDir`"",
    '--port=3307',
    '--bind-address=127.0.0.1',
    '--mysqlx-port=33061',
    "`"--log-error=$logFile`""
)
Start-Process -FilePath (Join-Path $mysqlHome 'bin\mysqld.exe') `
    -ArgumentList $argList `
    -WindowStyle Hidden

for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Port $port) {
        Write-Host "MySQL is ready on 127.0.0.1:$port"
        exit 0
    }
}

throw "MySQL did not start. Check $logFile"
