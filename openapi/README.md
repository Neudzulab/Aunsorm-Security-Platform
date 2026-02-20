# Aunsorm OpenAPI Documentation

Interactive API documentation for all Aunsorm microservices using OpenAPI 3.0 and Swagger UI.

## 🚀 Quick Start

### Start Documentation Server
```bash
cd openapi
docker compose up -d
```

### Set the Docs Host
Set the host placeholder used in links below to match your environment. Use the `HOST` override for any non-localhost deployments so docs links resolve correctly without hardcoding addresses:
```bash
export HOST=docs.aunsorm.local
```
To use the current machine IP or a remote domain, export the new value before opening the docs:
```bash
export HOST=10.10.12.25   # or docs.aunsorm.internal
```
For Windows PowerShell sessions, set the same variable like this:
```powershell
$env:HOST="docs.aunsorm.local"
```

### Access Documentation
- **Main Portal**: http://{host}:50024 (replace `{host}` with `$HOST`)
- **Swagger UI**: http://{host}:8080 (replace `{host}` with `$HOST`)
- **Redoc**: http://{host}:50025 (replace `{host}` with `$HOST`)
- **Individual Specs**: http://{host}:50024/[service-name].yaml (replace `{host}` with `$HOST`)

## 📚 Available Services

| Service | Port | Swagger UI Link | Redoc Link | Description |
|---------|------|-----------------|------------|-------------|
| **Auth** | 50011 | [Open](http://{host}:8080/?url=http://{host}:50024/auth-service.yaml) | [Open](http://{host}:50025/?url=/auth-service.yaml) | JWT, OAuth 2.0 + PKCE |
| **Crypto** | 50012 | [Open](http://{host}:8080/?url=http://{host}:50024/crypto-service.yaml) | [Open](http://{host}:50025/?url=/crypto-service.yaml) | AEAD, Signing, KDF |
| **PQC** | 50018 | [Open](http://{host}:8080/?url=http://{host}:50024/pqc-service.yaml) | [Open](http://{host}:50025/?url=/pqc-service.yaml) | ML-KEM, ML-DSA, SLH-DSA |
| **X509** | 50013 | [Planned](http://{host}:8080/?url=http://{host}:50024/x509-service.yaml) | [Planned](http://{host}:50025/?url=/x509-service.yaml) | Certificate Management (placeholder spec) |
| **KMS** | 50014 | [Planned](http://{host}:8080/?url=http://{host}:50024/kms-service.yaml) | [Planned](http://{host}:50025/?url=/kms-service.yaml) | Key Management (placeholder spec) |
| **MDM** | 50015 | [Planned](http://{host}:8080/?url=http://{host}:50024/mdm-service.yaml) | [Planned](http://{host}:50025/?url=/mdm-service.yaml) | Device enrollment and policy management (placeholder spec) |
| **ID** | 50016 | [Planned](http://{host}:8080/?url=http://{host}:50024/id-service.yaml) | [Planned](http://{host}:50025/?url=/id-service.yaml) | Unique ID lifecycle APIs (placeholder spec) |

## 📖 Interactive Testing

### Using Swagger UI

1. **Open Swagger UI**: Navigate to http://{host}:8080
2. **Select Service**: Use dropdown to choose Auth/Crypto/PQC service
3. **Try Endpoints**: 
   - Click "Try it out" on any endpoint
   - Fill in request parameters
   - Click "Execute"
   - View response

### Example: Generate JWT Token

```bash
# Using curl
curl -X POST http://{host}:50011/security/generate-media-token \
  -H "Content-Type: application/json" \
  -d '{
    "roomId": "test-room",
    "identity": "user123",
    "participantName": "TestUser"
  }'

# Using Swagger UI
1. Go to http://{host}:8080/?url=http://{host}:50024/auth-service.yaml
2. Navigate to POST /security/generate-media-token
3. Click "Try it out"
4. Fill in the request body
5. Click "Execute"
```

## 📁 File Structure

```
openapi/
├── auth-service.yaml          # Auth Service OpenAPI spec
├── crypto-service.yaml        # Crypto Service OpenAPI spec
├── id-service.yaml            # ID Service OpenAPI placeholder spec
├── kms-service.yaml           # KMS Service OpenAPI placeholder spec
├── mdm-service.yaml           # MDM Service OpenAPI placeholder spec
├── pqc-service.yaml          # PQC Service OpenAPI spec
├── x509-service.yaml          # X509 Service OpenAPI placeholder spec
├── docker-compose.yaml       # Swagger UI setup
├── nginx.conf                # Nginx config for serving specs
├── index.html                # Landing page
└── README.md                 # This file
```

## 🔧 Development

### Adding New Service Spec

1. Create `[service-name]-service.yaml`:
```yaml
openapi: 3.0.3
info:
  title: Service Name API
  version: 0.5.0
  description: Service description
servers:
  - url: http://{host}:PORT
paths:
  /endpoint:
    post:
      summary: Endpoint description
      # ... rest of spec
```

2. Update `index.html` to add service card

3. Restart documentation server:
```bash
docker compose restart
```

### Placeholder Spec Checklist

When a service is planned but not yet implemented, use a placeholder spec and keep
the documentation aligned with the planned status:

1. Mark the service links as **Planned** in the service table above.
2. Add "placeholder spec" language to the service description in the table.
3. Ensure the spec `info.description` explicitly states it is a placeholder and
   lists the planned scope.
4. Keep the placeholder spec limited to high-level paths and schemas; avoid
   implying endpoints are live.
5. Update `index.html` so the service card is labeled as planned.

### Validate OpenAPI Specs

```bash
# Install validator
npm install -g @apidevtools/swagger-cli

# Validate spec
swagger-cli validate auth-service.yaml
```

Validate all service specs in one pass:
```bash
for spec in *-service.yaml; do
  swagger-cli validate "$spec"
done
```

Generate docs catalog artifacts consumed by `docs/api` and CI:
```bash
cd ..
python3 scripts/generate_openapi_catalog.py
```

## 🎨 Features

### OpenAPI 3.0 Compliance
- ✅ Complete schema definitions
- ✅ Example requests/responses
- ✅ Security schemes (Bearer JWT)
- ✅ Error response models
- ✅ Base64 format specifications

### Interactive Swagger UI
- ✅ Try endpoints directly from browser
- ✅ Auto-completion for parameters
- ✅ Response validation
- ✅ Code generation (curl, Python, JS)

### Beautiful Landing Page
- ✅ Service cards with descriptions
- ✅ Direct Swagger UI links
- ✅ Quick start examples
- ✅ Responsive design

## 🔗 Integration

### Import into Postman
1. File → Import
2. Choose OpenAPI spec URL: `http://{host}:50024/auth-service.yaml`
3. Postman auto-generates collection

### Import into Insomnia
1. Create → Import from URL
2. Paste: `http://{host}:50024/crypto-service.yaml`
3. Test endpoints

### Generate Client Code
Swagger UI includes code generation for:
- curl
- Python (requests)
- JavaScript (fetch)
- Java
- Go
- And more...

## 📝 Best Practices

### Request Examples
All endpoints include realistic example values:
```yaml
properties:
  roomId:
    type: string
    example: test-room  # ✅ Helpful example
```

### Response Schemas
Complete response models with nested objects:
```yaml
schema:
  type: object
  properties:
    token:
      type: string
      example: eyJ0eXAiOiJKV1Q...
```

### Security Documentation
JWT authentication clearly documented:
```yaml
securitySchemes:
  BearerAuth:
    type: http
    scheme: bearer
    bearerFormat: JWT
```

## 🐛 Troubleshooting

### Swagger UI not loading
```bash
# Check if containers are running
docker ps | grep swagger

# View logs
docker logs aunsorm-swagger-ui
docker logs aunsorm-openapi-server
```

### CORS errors
CORS is configured in `nginx.conf`:
```nginx
add_header Access-Control-Allow-Origin *;
```

### Port conflicts
Edit `docker-compose.yaml` if ports 8080/50024 are in use:
```yaml
ports:
  - "9080:8080"  # Change Swagger UI external port
  - "50025:80"   # Change OpenAPI server external port
```

## 📚 Additional Resources

- [OpenAPI 3.0 Specification](https://swagger.io/specification/)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)
- [JWT Authentication Guide](../JWT_AUTHENTICATION_GUIDE.md)
- [Aunsorm GitHub](https://github.com/Neudzulab/aunsorm-crypt)

## 🚀 Production Deployment

### Nginx Production Config
```nginx
server {
    listen 443 ssl http2;
    server_name docs.aunsorm.production;
    
    ssl_certificate /etc/ssl/certs/docs.crt;
    ssl_certificate_key /etc/ssl/private/docs.key;
    
    location / {
        proxy_pass http://swagger-ui:8080;
    }
}
```

### Environment Variables
```bash
# Point to production APIs
SWAGGER_JSON_URL=https://api.aunsorm.production/specs.json
BASE_URL=/docs
```

## 📄 License

MIT License - see [LICENSE](../LICENSE)
