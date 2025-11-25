# Clock Attestation

## Rationale
Time skew enables replay of tokens and calibration material. Every service validates a signed snapshot containing `authority_id`, `authority_fingerprint_hex`, `unix_time_ms`, and network quality metrics. Stale attestations are rejected using `AUNSORM_CLOCK_MAX_AGE_SECS`.

## Configuration
- **Authority**: `AUNSORM_CALIBRATION_FINGERPRINT` must match the trusted signer.
- **Max Age**: Production uses `AUNSORM_CLOCK_MAX_AGE_SECS=30`; staging may relax to `300` with explicit approval.
- **Refresh**: Optional background worker enabled with `AUNSORM_CLOCK_REFRESH_URL` and `AUNSORM_CLOCK_REFRESH_INTERVAL_SECS` (≤ `max_age / 2`).

## Deployment Patterns
- **Managed NTP Attestor**: Deploy an internal attestation endpoint; services poll it for fresh JSON snapshots.
- **Offline Bootstrap**: Inject a fresh attestation into `.env` before startup for isolated environments.
- **Monitoring**: `/health` reports `clock.status`, `ageMs`, and `refreshEnabled` fields for alerting.

## Example Snapshot
```json
{
  "authority_id": "ntp.prod.aunsorm",
  "authority_fingerprint_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "unix_time_ms": 1735689600000,
  "stratum": 2,
  "round_trip_ms": 8,
  "dispersion_ms": 12,
  "estimated_offset_ms": 2,
  "signature_b64": "bW9jay1hdHRlc3RhdGlvbg"
}
```

## Troubleshooting
- `StaleAttestation`: Increase refresh cadence or provide a fresh snapshot.
- `UntrustedAuthority`: Update the fingerprint to the attested signer and restart.
