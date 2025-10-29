# Development NTP Mock Server
# Bu script local'de basit bir NTP attestation server simüle eder

param(
    [int]$Port = 5000,
    [string]$AuthorityId = "ntp.dev.aunsorm",
    [string]$Fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

Write-Host "🕐 Starting Dev NTP Attestation Server on http://localhost:$Port"
Write-Host "   Authority: $AuthorityId"
Write-Host "   Fingerprint: $Fingerprint"
Write-Host ""

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()

Write-Host "✅ Server running! Press Ctrl+C to stop."
Write-Host ""

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        if ($request.Url.AbsolutePath -eq "/attestation") {
            # Generate fresh timestamp
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            
            $attestation = @{
                authority_id = $AuthorityId
                authority_fingerprint_hex = $Fingerprint
                unix_time_ms = $now
                stratum = 2
                round_trip_ms = [System.Random]::new().Next(5, 15)
                dispersion_ms = [System.Random]::new().Next(8, 20)
                estimated_offset_ms = [System.Random]::new().Next(-5, 5)
                signature_b64 = "ZGV2X21vY2tfc2lnbmF0dXJl"
            } | ConvertTo-Json -Compress
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($attestation)
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()
            
            Write-Host "✓ Served attestation: $now" -ForegroundColor Green
        }
        else {
            $response.StatusCode = 404
            $response.Close()
        }
    }
}
finally {
    $listener.Stop()
    Write-Host "Server stopped."
}
