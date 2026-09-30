$zipPath = "C:\Users\Sweta\Desktop\Orion_v2_Distribution.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
$files = Get-ChildItem -Path "C:\Users\Sweta\Desktop\Orion_v2" -Recurse | Where-Object {
    $p = $_.FullName
    -not $_.PSIsContainer -and
    $p -notmatch '\\(\.git|\.pytest_cache|__pycache__|node_modules|dist)\\' -and
    $p -notmatch '\.(pyc|log|db)$'
}
Compress-Archive -Path $files.FullName -DestinationPath $zipPath -CompressionLevel Optimal
$count = $files.Count
Write-Host "Archived $count files to $zipPath"
