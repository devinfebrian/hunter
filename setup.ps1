# Hunter Setup Script for Windows (PowerShell)

Write-Host "Setting up Hunter virtual environment..." -ForegroundColor Cyan

# Check if venv exists
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
. .\.venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Create output directory
if (-not (Test-Path "output")) {
    New-Item -ItemType Directory -Path "output" | Out-Null
}

Write-Host "" -ForegroundColor Green
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "To activate the virtual environment, run:" -ForegroundColor Cyan
Write-Host "    .venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "" -ForegroundColor Cyan
Write-Host "To run Hunter:" -ForegroundColor Cyan
Write-Host "    python -m hunter --help" -ForegroundColor White
