# Aunsorm Web Integrations Helpers

The web integration utilities provide deterministic helpers that web clients can
use to configure OAuth flows and resolve the correct base URL for the Aunsorm
services. They live in [`apps/web/lib`](./lib) and are designed to operate in
strictly controlled environments where environment variables may come from
multiple deployment platforms.

## Base URL resolution precedence

`resolveAunsormBaseUrl` applies a layered precedence model when constructing the
final URL that client integrations should target.

1. **File-based overrides** – variables ending with `_BASE_URL_FILE` take the
   highest precedence. When one of these is set the helper reads the referenced
   file and returns its trimmed contents as-is. Any direct or domain/path
   overrides are ignored in this mode.
2. **Direct environment overrides** – if no file-based override is present, the
   helper looks for the `_BASE_URL` variables. A non-empty trimmed value is
   treated as the full URL (without automatic trailing slash insertion). When
   active, domain and path overrides are ignored.
3. **Domain/path composition** – when only domain or path overrides are set the
   helper composes the URL using the deployment defaults for the current
   `NODE_ENV` (`https://aunsorm.dev/aunsorm` in production,
   `http://localhost:50047/aunsorm` otherwise). Loopback hosts force the scheme
   to `http`.
4. **Fallback defaults** – when no overrides are provided the helper returns the
   defaults for the active environment (`production` vs. `other`).

The companion `resolveAunsormBaseUrlDiagnostics` utility surfaces warnings when
conflicting variables are present so deployment pipelines can fail fast instead
of silently picking one value.

## Loopback and preview domain handling

Both direct overrides and composed domains are normalised to detect loopback
addresses. Known aliases (such as `localhost6` or IPv6-mapped IPv4 addresses)
are coerced to `http` even when `NODE_ENV=production`, ensuring local testing
remains consistent.

## Testing

All helpers ship with Vitest coverage in
[`experimental-integrations.test.ts`](./lib/experimental-integrations.test.ts).
Run `npm test` from this directory to execute the suite.

## OAuth client usage notes

`AunsormOAuthClient` persists the PKCE verifier and state in the configured
storage adapter when `beginAuthorization` is invoked. If the consumer does not
provide a storage implementation (for example in frameworks where session
storage is unavailable) the helper now accepts an optional `expectedState`
override when calling `handleCallback`. This allows clients to compare the
state value received from the authorization server against the state returned by
`beginAuthorization` without giving up on CSRF protection.

When both a storage adapter and an explicit override are supplied the helper
verifies that the values match to prevent confusing state mismatches.

### Refresh token persistence

`AunsormOAuthClient` also keeps the most recent refresh token in the configured
storage adapter (under `aunsorm.oauth.refresh_token`).

- `exchangeToken` persists both the access token and refresh token when the
  server issues them.
- `refreshAccessToken` automatically reuses the stored refresh token when one is
  available and rotates it whenever the server responds with a new value.
- When storage is unavailable, callers can pass a `refreshToken` override to
  `refreshAccessToken`.

Consumers that need to explicitly remove the stored secret can call
`clearStoredRefreshToken()`.
