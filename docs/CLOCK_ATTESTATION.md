# Clock Attestation Configuration

## 🎯 Overview

Aunsorm uses **NTP-style clock attestation** to prevent time-based replay attacks and ensure cryptographic operations happen within trusted time windows.

## 🔒 Security Model

### Why Clock Attestation?

```
WITHOUT ATTESTATION:
┌─────────────────────────────────────────┐
│ Attacker steals JWT token from 2023     │
│ → Sets system clock to 2023             │
│ → Token still valid! ❌                 │
└─────────────────────────────────────────┘

WITH ATTESTATION:
┌─────────────────────────────────────────┐
│ Trusted NTP authority signs timestamp   │
│ → "This operation happened at X time"   │
│ → Old attestations rejected             │
│ → Replay attacks prevented ✅           │
└─────────────────────────────────────────┘
```

### 30-Second Max Age

The `max_age` parameter defines how long a clock attestation remains valid:

```rust
// Production: Strict 30-second window
Duration::from_secs(30)

// Why 30 seconds?
// 1. Prevents replay attacks (old attestations unusable)
// 2. Ensures fresh time source
// 3. Requires active NTP refresh service
```

---

## 🏭 Production Deployment

### Option 1: External NTP Service (Recommended)

Deploy a dedicated NTP attestation service that signs fresh timestamps:

```yaml
# docker-compose.yml
services:
  ntp-attestation:
    image: aunsorm-ntp-server:latest
    environment:
      - NTP_AUTHORITY_ID=ntp.prod.aunsorm
      - NTP_SIGNING_KEY_PATH=/secrets/ntp-signing-key.pem
      - REFRESH_INTERVAL_SECS=15  # Refresh every 15s for 30s max_age
    volumes:
      - ./secrets:/secrets:ro
    ports:
      - "5001:5000"

  auth-service:
    depends_on:
      - ntp-attestation
    environment:
      - AUNSORM_NTP_URL=http://ntp-attestation:5000/attestation
      - AUNSORM_CLOCK_MAX_AGE_SECS=30  # Production strict
```

### Option 2: Manual Script Refresh

Use the provided PowerShell script to generate fresh attestations:

```powershell
# Start the dev NTP server
.\scripts\dev-ntp-server.ps1 -Port 5001

# Services will fetch from http://localhost:5001/attestation
```

### Option 3: Environment Variable Refresh Script

For staging/testing environments, auto-update `.env`:

```powershell
# refresh-attestation.ps1
while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $attestation = @{
        authority_id = "ntp.staging.aunsorm"
        authority_fingerprint_hex = "bbbb..."
        unix_time_ms = $now
        stratum = 2
        round_trip_ms = 10
        dispersion_ms = 15
        estimated_offset_ms = 0
        signature_b64 = "c3RhZ2luZ19zaWdu"
    } | ConvertTo-Json -Compress
    
    $content = Get-Content .env -Raw
    $content = $content -replace 'AUNSORM_CLOCK_ATTESTATION=.*', "AUNSORM_CLOCK_ATTESTATION=$attestation"
    Set-Content .env $content -NoNewline
    
    Write-Host "✓ Attestation refreshed: $now"
    Start-Sleep -Seconds 15
}
```

---

## 🧪 Development/Staging Configuration

### Relaxed Max Age

For development environments where NTP refresh isn't available:

```bash
# .env
AUNSORM_CLOCK_MAX_AGE_SECS=300  # 5 minutes tolerance

# Manually update timestamp occasionally:
AUNSORM_CLOCK_ATTESTATION={"authority_id":"ntp.dev.aunsorm",...,"unix_time_ms":1730236800000,...}
```

**⚠️ Warning**: Never use `max_age > 60` in production!

---

## 🔄 Clock Refresh Service Integration

### Automatic Refresh (Future Implementation)

The `ClockRefreshService` can automatically fetch fresh attestations:

```rust
use aunsorm_server::ClockRefreshService;
use std::sync::Arc;
use std::time::Duration;

// Initialize refresh service
let refresh_service = Arc::new(ClockRefreshService::new(
    initial_snapshot,
    Some("http://ntp-server:5000/attestation".to_string()),
    Duration::from_secs(15),  // Refresh every 15s
));

// Start background refresh task
let _refresh_handle = refresh_service.clone().start();

// Get current attestation
let current_snapshot = refresh_service.get_current().await;
```

---

## 📋 Environment Variables

| Variable | Default | Production | Description |
|----------|---------|------------|-------------|
| `AUNSORM_CLOCK_ATTESTATION` | *required* | From NTP | JSON clock snapshot |
| `AUNSORM_CLOCK_MAX_AGE_SECS` | `30` | `30` | Max attestation age (seconds) |
| `AUNSORM_NTP_URL` | `None` | `http://ntp:5000/attestation` | NTP service endpoint |
| `AUNSORM_CALIBRATION_FINGERPRINT` | *required* | Production cert | Calibration cert fingerprint |

---

## 🔍 Verification

### Check Current Attestation

```bash
# View current attestation in logs
docker compose logs auth-service | grep "Clock"

# Expected output:
# ✓ Clock attestation validated: unix_time_ms=1730236800000
# ⚠️ Clock max_age set to 300 seconds (production should use ≤30s)
```

### Test Freshness

```bash
# Stop NTP refresh and wait 31+ seconds
# Services should fail with StaleAttestation error:
# Error: Clock(StaleAttestation { age_ms: 31000, max_ms: 30000 })
```

---

## 🛡️ Security Best Practices

1. **Production**: Always use `max_age ≤ 30` seconds
2. **NTP Authority**: Use trusted, authenticated NTP source
3. **Signature Validation**: Verify NTP signatures cryptographically (future)
4. **Monitoring**: Alert on attestation refresh failures
5. **Rotation**: Rotate NTP signing keys regularly

---

## 🐛 Troubleshooting

### StaleAttestation Error

```
Error: Clock(StaleAttestation { age_ms: 35000, max_ms: 30000 })
```

**Cause**: Attestation older than `max_age`

**Solutions**:
- Update `AUNSORM_CLOCK_ATTESTATION` with fresh timestamp
- Deploy NTP refresh service
- Increase `AUNSORM_CLOCK_MAX_AGE_SECS` (staging only)

### UntrustedAuthority Error

```
Error: Clock(UntrustedAuthority { fingerprint_hex: "xxxx..." })
```

**Cause**: Authority fingerprint not in trusted list

**Solution**: Ensure `authority_fingerprint_hex` in attestation matches configured authority

---

## 📚 References

- [RFC 8915: NTP Security](https://datatracker.ietf.org/doc/html/rfc8915)
- [Time-Based Security in Distributed Systems](https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-corbett.pdf)
- Aunsorm Core: `crates/core/src/clock.rs`
