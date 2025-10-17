# OAuth2 + Aunsorm Integration Request (Issue #12)

**Status:** 🚧 Blocked - Rust endpoint schema incompatible  
**Priority:** HIGH  
**Target Version:** v0.4.6  
**RFCs:** RFC 6749 (OAuth 2.0), RFC 7636 (PKCE)

## Problem Statement

The current `/oauth/begin-auth` endpoint schema is **incompatible with standard OAuth2 authorization flows**. It uses a custom `username` field instead of RFC 6749 compliant parameters, blocking web app integrations that expect:

1. **Authorization endpoint** (`/oauth/begin-auth`) → Should accept `redirect_uri`, `state`, `scope`
2. **Token endpoint** (`/oauth/token`) → Should validate `redirect_uri` match
3. **PKCE flow** → Currently supports S256 but lacks standard OAuth2 params

## Current Schema (Incompatible)

```rust
// crates/server/src/routes.rs - Line 256
#[derive(Debug, Deserialize)]
struct BeginAuthRequest {
    username: String,          // ❌ Non-standard field
    client_id: String,         // ✅ OAuth2 standard
    code_challenge: String,    // ✅ PKCE (RFC 7636)
    code_challenge_method: String, // ✅ PKCE
}
```

**Issues:**
- ❌ `username` field forces client-side authentication before OAuth flow
- ❌ Missing `redirect_uri` (required for web app callback)
- ❌ Missing `state` (CSRF protection, RFC 6749 §10.12)
- ❌ Missing `scope` (permission delegation)
- ❌ Response returns `auth_request_id` instead of `code` (authorization code)

## Required Schema (RFC 6749/7636 Compliant)

### Authorization Request

```rust
#[derive(Debug, Deserialize)]
struct BeginAuthRequest {
    client_id: String,            // ✅ OAuth2 required
    redirect_uri: String,         // ✅ OAuth2 required (callback URL)
    state: Option<String>,        // ✅ OAuth2 recommended (CSRF token)
    scope: Option<String>,        // ✅ OAuth2 optional (e.g., "read write")
    code_challenge: String,       // ✅ PKCE required
    code_challenge_method: String, // ✅ PKCE required (must be "S256")
    
    // Optional: If server needs to pre-populate user context
    subject: Option<String>,      // ✅ Optional hint (not username)
}
```

### Authorization Response

```rust
#[derive(Debug, Serialize)]
struct BeginAuthResponse {
    code: String,              // ✅ OAuth2 authorization code
    state: Option<String>,     // ✅ Echo client's state (CSRF validation)
    expires_in: u64,           // ✅ Code expiry (seconds)
}
```

## Field Specifications

| Field | Type | Required | Description | RFC Reference |
|-------|------|----------|-------------|---------------|
| `client_id` | String | ✅ Yes | Registered client identifier | RFC 6749 §4.1.1 |
| `redirect_uri` | String | ✅ Yes | Callback URL (must be pre-registered) | RFC 6749 §3.1.2 |
| `state` | String | ⚠️ Recommended | Opaque CSRF token (echoed back) | RFC 6749 §10.12 |
| `scope` | String | ❌ Optional | Space-delimited permissions | RFC 6749 §3.3 |
| `code_challenge` | String | ✅ Yes (PKCE) | Base64-URL(SHA256(code_verifier)) | RFC 7636 §4.2 |
| `code_challenge_method` | String | ✅ Yes (PKCE) | Must be "S256" | RFC 7636 §4.3 |
| `subject` | String | ❌ Optional | User hint (not for authentication) | Extension |

## Validation Rules

### 1. `redirect_uri` Validation

```rust
// Must be a valid HTTPS URL (HTTP allowed for localhost only)
fn validate_redirect_uri(uri: &str) -> Result<(), ApiError> {
    let url = Url::parse(uri)
        .map_err(|_| ApiError::invalid_request("redirect_uri must be a valid URL"))?;
    
    match url.scheme() {
        "https" => Ok(()),
        "http" if url.host_str() == Some("localhost") || url.host_str() == Some("127.0.0.1") => Ok(()),
        _ => Err(ApiError::invalid_request("redirect_uri must use HTTPS")),
    }
}

// Must match pre-registered client URIs (prevent open redirect)
if !state.is_redirect_uri_registered(client_id, redirect_uri) {
    return Err(ApiError::invalid_client("redirect_uri not registered"));
}
```

### 2. `state` Handling

```rust
// Server must store state in auth session and echo it back
let auth_session = AuthSession {
    code: generate_authorization_code(),
    client_id: client_id.clone(),
    redirect_uri: redirect_uri.clone(),
    state: state.clone(),  // Store for validation in /oauth/token
    code_challenge,
    code_challenge_method,
    created_at: SystemTime::now(),
    expires_at: SystemTime::now() + Duration::from_secs(600), // 10 min
};
```

### 3. `scope` Processing

```rust
// Parse space-delimited scopes
let requested_scopes: Vec<&str> = scope
    .as_deref()
    .unwrap_or("default")
    .split_whitespace()
    .collect();

// Validate against allowed scopes for client
for scope in &requested_scopes {
    if !state.is_scope_allowed(client_id, scope) {
        return Err(ApiError::invalid_scope("scope not allowed"));
    }
}
```

## Token Exchange Flow

### 1. Client Calls `/oauth/begin-auth`

```bash
POST /oauth/begin-auth
Content-Type: application/json

{
  "client_id": "webapp-123",
  "redirect_uri": "https://app.example.com/callback",
  "state": "xyz-random-csrf-token",
  "scope": "read write",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256"
}
```

**Response:**
```json
{
  "code": "auth_abc123xyz",
  "state": "xyz-random-csrf-token",
  "expires_in": 600
}
```

### 2. Client Redirects to `redirect_uri` with Code

```
https://app.example.com/callback?code=auth_abc123xyz&state=xyz-random-csrf-token
```

### 3. Client Calls `/oauth/token` (Unchanged)

```bash
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "auth_abc123xyz",
  "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "client_id": "webapp-123",
  "redirect_uri": "https://app.example.com/callback"  # Must match
}
```

## Implementation Checklist

### Backend (Rust - Platform Agent)

- [ ] Update `BeginAuthRequest` struct (remove `username`, add `redirect_uri`, `state`, `scope`, `subject`)
- [ ] Add `redirect_uri` validation (HTTPS, URL format, registration check)
- [ ] Store `state` and `scope` in auth session (`ServerState::auth_sessions`)
- [ ] Return `code` instead of `auth_request_id` in response
- [ ] Echo `state` in response
- [ ] Update `exchange_token` to validate `redirect_uri` match
- [ ] Add `scope` to generated JWT claims
- [ ] Add error responses: `invalid_scope`, `invalid_redirect_uri`

### Frontend (Web App Integration)

- [ ] Implement PKCE S256 client (generate `code_verifier`, compute `code_challenge`)
- [ ] Generate random `state` (CSRF token, store in sessionStorage)
- [ ] Call `/oauth/begin-auth` with all required params
- [ ] Handle `code` + `state` in callback route
- [ ] Validate returned `state` matches stored value
- [ ] Call `/oauth/token` with `code_verifier` and `redirect_uri`
- [ ] Store access token securely (HttpOnly cookie or sessionStorage)

### Documentation

- [ ] Update `README.md` OAuth2 section with new schema examples
- [ ] Create `docs/operations/oauth-web-integration.md` (PKCE client guide)
- [ ] Add OpenAPI/Swagger spec for updated endpoints
- [ ] Document redirect URI registration process

### Testing

- [ ] Add `tests/oauth_rfc_compliance.rs`:
  - [ ] Test full authorization code flow
  - [ ] Test PKCE S256 validation
  - [ ] Test `redirect_uri` security (open redirect prevention)
  - [ ] Test `state` replay protection
  - [ ] Test invalid scope rejection
  - [ ] Test missing required params (400 errors)

## Security Considerations

### 1. Open Redirect Prevention

```rust
// CRITICAL: Never trust redirect_uri without validation
// Attack: https://auth.example.com/oauth/begin-auth?redirect_uri=https://evil.com

impl ServerState {
    fn is_redirect_uri_registered(&self, client_id: &str, uri: &str) -> bool {
        // Check against pre-registered URIs in database/config
        self.registered_clients
            .get(client_id)
            .map_or(false, |client| client.redirect_uris.contains(&uri.to_owned()))
    }
}
```

### 2. State Parameter (CSRF Protection)

```rust
// Client generates random state, server echoes it
// Client MUST validate state matches before token exchange
// Prevents authorization code interception attacks
```

### 3. Authorization Code Reuse

```rust
// Code must be single-use and short-lived (10 min)
if state.consume_auth_code(&code).is_none() {
    return Err(ApiError::invalid_grant("code already used or expired"));
}
```

## Migration Path (Breaking Change)

**⚠️ BREAKING CHANGE:** Existing clients using `username` field will break.

**Migration Strategy:**

1. **v0.4.6 (This Release):**
   - Add new RFC-compliant schema
   - Mark old schema as deprecated (log warning)
   - Support both schemas temporarily (6 months)

2. **v0.5.0 (Q1 2026):**
   - Remove `username` field support
   - Enforce RFC compliance

**Backward Compatibility (Temporary):**

```rust
#[derive(Debug, Deserialize)]
struct BeginAuthRequest {
    // New RFC fields
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    state: Option<String>,
    
    // Legacy field (deprecated)
    #[serde(default)]
    #[deprecated(since = "0.4.6", note = "Use subject instead")]
    username: Option<String>,
    
    // Standard fields
    client_id: String,
    code_challenge: String,
    code_challenge_method: String,
}
```

## Example Integration (JavaScript/TypeScript)

```typescript
// PKCE Client Implementation
class AunsormOAuthClient {
  private codeVerifier: string;
  private state: string;

  async authorize(clientId: string, redirectUri: string, scope: string) {
    // 1. Generate PKCE parameters
    this.codeVerifier = this.generateRandomString(43);
    this.state = this.generateRandomString(32);
    
    const codeChallenge = await this.sha256Base64Url(this.codeVerifier);
    
    // 2. Store state for validation
    sessionStorage.setItem('oauth_state', this.state);
    
    // 3. Call authorization endpoint
    const response = await fetch('https://auth.example.com/oauth/begin-auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: clientId,
        redirect_uri: redirectUri,
        state: this.state,
        scope: scope,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }),
    });
    
    const { code, state } = await response.json();
    
    // 4. Validate state
    if (state !== this.state) {
      throw new Error('State mismatch (CSRF detected)');
    }
    
    // 5. Exchange code for token
    return this.exchangeToken(clientId, redirectUri, code);
  }
  
  private async exchangeToken(clientId: string, redirectUri: string, code: string) {
    const response = await fetch('https://auth.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        code_verifier: this.codeVerifier,
        client_id: clientId,
        redirect_uri: redirectUri,
      }),
    });
    
    return response.json(); // { access_token, token_type, expires_in }
  }
  
  private generateRandomString(length: number): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  private async sha256Base64Url(input: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
```

## References

- **RFC 6749:** OAuth 2.0 Authorization Framework - https://www.rfc-editor.org/rfc/rfc6749.html
- **RFC 7636:** PKCE (Proof Key for Code Exchange) - https://www.rfc-editor.org/rfc/rfc7636.html
- **RFC 6750:** OAuth 2.0 Bearer Token Usage - https://www.rfc-editor.org/rfc/rfc6750.html
- **OWASP OAuth Security Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

## Contact

- **Responsible Agent:** Platform Agent (crates/server)
- **Blocked By:** Schema incompatibility
- **Unblocks:** Web app integration, mobile app OAuth flow
- **Issue Tracker:** #12
