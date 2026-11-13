param(
    [switch]$VerifyOnly,
    [string]$AssetRoot
)
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($AssetRoot)) {
    $AssetRoot = Join-Path $projectRoot 'src-tauri/llm-assets'
}
$cache = Join-Path $projectRoot 'src-tauri/target/llm-staging'
$modelName = 'qwen2.5-1.5b-instruct-q4_k_m.gguf'
$modelSize = [int64]1117320736
$modelSha = '6A1A2EB6D15622BF3C96857206351BA97E1AF16C30D7A74EE38970E434E9407E'
$serverSize = [int64]9728
$serverSha = 'DFD23267C514F055EC7A0357175D47D79AF79BFCED21BE0E969E08E8DE24D1F6'
$archiveName = 'llama-b12244-bin-win-cpu-x64.zip'
$archiveSize = [int64]24930349
$archiveSha = '318F11FADCBC3A86541EC55D9930CC76646C6B8D2FF18798C8477E9FF0DC452A'

function Assert-PinnedFile([string]$Path, [int64]$Size, [string]$Sha) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing bundled asset: $Path" }
    if ((Get-Item -LiteralPath $Path).Length -ne $Size) { throw "Bundled asset size differs: $Path" }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Sha) {
        throw "Bundled asset checksum differs: $Path"
    }
}

function Ensure-PinnedDownload([string]$Path, [string]$Url, [int64]$Size, [string]$Sha) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { Assert-PinnedFile $Path $Size $Sha; return } catch { Write-Warning $_.Exception.Message }
    }
    $partial = "$Path.partial"
    Write-Host "Downloading pinned asset: $(Split-Path $Path -Leaf)"
    Invoke-WebRequest -Uri $Url -OutFile $partial
    Assert-PinnedFile $partial $Size $Sha
    Move-Item -LiteralPath $partial -Destination $Path -Force
}

function Assert-Bundle([string]$Root) {
    Assert-PinnedFile (Join-Path $Root 'model.gguf') $modelSize $modelSha
    Assert-PinnedFile (Join-Path $Root 'runtime/llama-server.exe') $serverSize $serverSha
    foreach ($name in @('ggml.dll','ggml-base.dll','ggml-cpu-x64.dll','llama.dll',
                        'llama-common.dll','llama-server-impl.dll','libomp.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root "runtime/$name") -PathType Leaf)) {
            throw "Missing bundled runtime dependency: $name"
        }
    }
    Assert-PinnedFile (Join-Path $Root 'LICENSE-llama.cpp') 1078 '94F29BBED6A22C35B992C5C6EBF0E7C92F13B836B90F36F461C9CF2F0F1D010D'
    Assert-PinnedFile (Join-Path $Root 'LICENSE-Qwen') 11343 '832DD9E00A68DD83B3C3FB9F5588DAD7DCF337A0DB50F7D9483F310CD292E92E'
    Assert-PinnedFile (Join-Path $Root 'LICENSE-LLVM-OpenMP') 19741 'FDAD1758A9E1F9D5A81E18879B3406772115EDC92C24BFA36B70C654F325E8E4'
}

if ($VerifyOnly) {
    Assert-Bundle $AssetRoot
    Write-Host 'Bundled local model and runtime verified.'
    return
}

New-Item -ItemType Directory -Force -Path $cache, $AssetRoot, (Join-Path $AssetRoot 'runtime') | Out-Null
$archive = Join-Path $cache $archiveName
$model = Join-Path $cache $modelName
Ensure-PinnedDownload $archive "https://github.com/ggml-org/llama.cpp/releases/download/b12244/$archiveName" $archiveSize $archiveSha
Ensure-PinnedDownload $model "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/91cad51170dc346986eccefdc2dd33a9da36ead9/$modelName`?download=true" $modelSize $modelSha

$extracted = Join-Path $cache 'runtime'
if (-not (Test-Path -LiteralPath (Join-Path $extracted 'llama-server.exe') -PathType Leaf)) {
    Expand-Archive -LiteralPath $archive -DestinationPath $extracted -Force
}
Assert-PinnedFile (Join-Path $extracted 'llama-server.exe') $serverSize $serverSha
Copy-Item -LiteralPath (Join-Path $extracted 'llama-server.exe') -Destination (Join-Path $AssetRoot 'runtime/llama-server.exe') -Force
Get-ChildItem -LiteralPath $extracted -Filter '*.dll' -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $AssetRoot "runtime/$($_.Name)") -Force
}
if (-not (Test-Path -LiteralPath (Join-Path $AssetRoot 'model.gguf') -PathType Leaf) -or
    (Get-Item -LiteralPath (Join-Path $AssetRoot 'model.gguf')).Length -ne $modelSize) {
    Copy-Item -LiteralPath $model -Destination (Join-Path $AssetRoot 'model.gguf') -Force
}

$llamaLicense = Join-Path $cache 'LICENSE-llama.cpp'
$qwenLicense = Join-Path $cache 'LICENSE-Qwen'
Ensure-PinnedDownload $llamaLicense 'https://raw.githubusercontent.com/ggml-org/llama.cpp/b12244/LICENSE' 1078 '94F29BBED6A22C35B992C5C6EBF0E7C92F13B836B90F36F461C9CF2F0F1D010D'
Ensure-PinnedDownload $qwenLicense 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/91cad51170dc346986eccefdc2dd33a9da36ead9/LICENSE?download=true' 11343 '832DD9E00A68DD83B3C3FB9F5588DAD7DCF337A0DB50F7D9483F310CD292E92E'
Copy-Item -LiteralPath $llamaLicense -Destination (Join-Path $AssetRoot 'LICENSE-llama.cpp') -Force
Copy-Item -LiteralPath $qwenLicense -Destination (Join-Path $AssetRoot 'LICENSE-Qwen') -Force
Copy-Item -LiteralPath (Join-Path $extracted 'LICENSE-LLVM-OpenMP') -Destination (Join-Path $AssetRoot 'LICENSE-LLVM-OpenMP') -Force
Assert-Bundle $AssetRoot
Write-Host 'Bundled local model and runtime verified.'
