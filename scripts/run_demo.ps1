$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Vault = Join-Path $ProjectRoot "vault"
$Outputs = Join-Path $ProjectRoot "outputs\demo_run"
$Recovered = Join-Path $Outputs "recovered.txt"
$Plain = Join-Path $ProjectRoot "demo_files\plain.txt"
$TamperRoot = Join-Path $ProjectRoot "vault_tamper_cases"
$Log = Join-Path $Outputs "demo_log.txt"
$Password = "test123"

function Remove-WorkspacePath {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not $resolved.StartsWith($ProjectRoot)) {
        throw "Refusing to remove outside project: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Invoke-Logged {
    param([string]$Title, [scriptblock]$Command)
    "===== $Title =====" | Tee-Object -FilePath $Log -Append
    & $Command 2>&1 | Tee-Object -FilePath $Log -Append
    "" | Tee-Object -FilePath $Log -Append
}

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Virtual environment Python not found: $Python"
}

Remove-WorkspacePath $Vault
Remove-WorkspacePath $Outputs
Remove-WorkspacePath $TamperRoot
New-Item -ItemType Directory -Force -Path $Outputs | Out-Null

"AES-GCM Merkle archive demo run" | Set-Content -Path $Log -Encoding UTF8
"Project: $ProjectRoot" | Add-Content -Path $Log -Encoding UTF8
"Time: $(Get-Date -Format s)" | Add-Content -Path $Log -Encoding UTF8
"" | Add-Content -Path $Log -Encoding UTF8

Invoke-Logged "create archive" {
    & $Python -m archive_tool.main create $Vault --chunk-size 64 --password $Password
}

$encryptOutput = & $Python -m archive_tool.main encrypt $Vault $Plain --password $Password
"===== encrypt file =====" | Tee-Object -FilePath $Log -Append
$encryptOutput | Tee-Object -FilePath $Log -Append
"" | Tee-Object -FilePath $Log -Append
$FileId = ($encryptOutput | Where-Object { $_ -like "file_id:*" }) -replace "file_id:\s*", ""
if (-not $FileId) {
    throw "Could not parse file_id from encrypt output."
}

Invoke-Logged "list archive" {
    & $Python -m archive_tool.main list $Vault --password $Password
}

Invoke-Logged "verify archive" {
    & $Python -m archive_tool.main verify $Vault --password $Password
}

Invoke-Logged "decrypt file" {
    & $Python -m archive_tool.main decrypt $Vault $FileId $Recovered --password $Password
}

"===== sha256 comparison =====" | Tee-Object -FilePath $Log -Append
$PlainHash = (Get-FileHash -LiteralPath $Plain -Algorithm SHA256).Hash
$RecoveredHash = (Get-FileHash -LiteralPath $Recovered -Algorithm SHA256).Hash
"plain_sha256=$PlainHash" | Tee-Object -FilePath $Log -Append
"recovered_sha256=$RecoveredHash" | Tee-Object -FilePath $Log -Append
if ($PlainHash -ne $RecoveredHash) {
    throw "Recovered file hash mismatch."
}
"sha256_match=True" | Tee-Object -FilePath $Log -Append
"" | Tee-Object -FilePath $Log -Append

Invoke-Logged "tamper test" {
    & $Python -m archive_tool.main tamper-test $Vault --password $Password
}

"Demo log saved to: $Log"
