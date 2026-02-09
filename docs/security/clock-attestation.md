# Clock Attestation

## Rationale
Time skew enables replay of tokens and calibration material. Every service validates a signed snapshot containing `authority_id`, `authority_fingerprint_hex`, `unix_time_ms`, and network quality metrics. Stale attestations are rejected using `AUNSORM_CLOCK_MAX_AGE_SECS`.

## Configuration
- **Authority**: `AUNSORM_CALIBRATION_FINGERPRINT` must match the trusted signer.
- **Max Age**: Production uses `AUNSORM_CLOCK_MAX_AGE_SECS=30`; staging may relax to `300` with explicit approval.
- **Refresh**: Optional background worker enabled with `AUNSORM_CLOCK_REFRESH_URL` and `AUNSORM_CLOCK_REFRESH_INTERVAL_SECS` (≤ `max_age / 2`).

## Production Requirements
- **Real NTP Attestation Server**: Deploy a dedicated NTP attestation service that signs snapshots with production certificates.
- **Dual-Node HA**: Provision two attestation nodes with hardware PPS/GPS modules and front them with HAProxy failover.
- **Production CA Issuance**: Issue attestation certificates from the production CA; do not use development CAs in production.
- **Key Rotation**: Rotate attestation signing keys quarterly and publish updated fingerprints before cutover.
- **No Mock Signatures**: Development-only mock signatures are forbidden in production; snapshots must include real cryptographic proofs.
- **Strict Max Age**: Enforce `AUNSORM_CLOCK_MAX_AGE_SECS=30` in production environments.

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
`signature_b64` above is truncated placeholder data for documentation only; production snapshots must include a real signature.

## Troubleshooting
- `StaleAttestation`: Increase refresh cadence or provide a fresh snapshot.
- `UntrustedAuthority`: Update the fingerprint to the attested signer and restart.
