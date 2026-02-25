param(
  [string]$BaseUrl = "http://localhost:5173",
  [string]$AdminKey = ""
)

$ErrorActionPreference = 'Stop'

Write-Host "Running prelaunch checks against $BaseUrl" -ForegroundColor Cyan

function Check-JsonEndpoint {
  param([string]$Url)
  $resp = Invoke-RestMethod -Method Get -Uri $Url
  return $resp
}

$health = Check-JsonEndpoint "$BaseUrl/api/health"
Write-Host "Health ok: $($health.ok) env=$($health.env) emailMode=$($health.emailDeliveryMode)" -ForegroundColor Yellow

if ($health.env -eq 'production' -and -not $health.ok) {
  Write-Host "Production config errors:" -ForegroundColor Red
  $health.productionErrors | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
  exit 1
}

$rootStatus = (Invoke-WebRequest -UseBasicParsing -Uri $BaseUrl).StatusCode
Write-Host "Root status: $rootStatus" -ForegroundColor Green

try {
  Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/data/app-data.json" | Out-Null
  Write-Host "ERROR: data/app-data.json is publicly accessible" -ForegroundColor Red
  exit 1
} catch {
  Write-Host "Sensitive data file blocked: OK" -ForegroundColor Green
}

if ($AdminKey) {
  try {
    $headers = @{ 'x-admin-key' = $AdminKey }
    $adminStatus = (Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/api/admin/users-overview" -Headers $headers).StatusCode
    Write-Host "Admin overview status with header key: $adminStatus" -ForegroundColor Green
  } catch {
    Write-Host "Admin overview check failed with provided key" -ForegroundColor Red
    exit 1
  }
}

Write-Host "Prelaunch checks completed." -ForegroundColor Cyan
