# API References

## Specifications
- OpenAPI specs live under `openapi/` per service (gateway, auth, crypto, kms, acme, pqc).
- Swagger UI: http://localhost:8080
- Redoc: http://localhost:50025
- Spec server: http://localhost:50024

## Conventions
- JSON fields use camelCase; custom claims are nested under `extras`.
- All responses return explicit `Content-Type` headers.
- Calibration headers must be forwarded by clients when provided by upstream services.

## Sample Request
```bash
curl -X POST http://localhost:50011/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"sample","code_verifier":"verifier","client_id":"cli","redirect_uri":"https://client/callback"}'
```

## Sample Response
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "jti": "example-jti"
}
```

## Validation
- Update the corresponding `openapi/*` files when endpoints change.
- Keep port bindings synchronized with `port-map.yaml` and `.env.example`.
