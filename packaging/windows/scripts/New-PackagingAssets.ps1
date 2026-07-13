[CmdletBinding()]
param([Parameter(Mandatory)][string] $OutputDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw "output directory already exists: $OutputDirectory" }
Add-Type -AssemblyName System.Drawing
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
foreach ($asset in @(
  @{ Name = 'StoreLogo.png'; Size = 50 },
  @{ Name = 'Square150x150Logo.png'; Size = 150 },
  @{ Name = 'Square44x44Logo.png'; Size = 44 }
)) {
  $bitmap = [System.Drawing.Bitmap]::new($asset.Size, $asset.Size)
  try {
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try { $graphics.Clear([System.Drawing.Color]::FromArgb(255, 20, 23, 31)) } finally { $graphics.Dispose() }
    $bitmap.Save((Join-Path $OutputDirectory $asset.Name), [System.Drawing.Imaging.ImageFormat]::Png)
  } finally { $bitmap.Dispose() }
}
