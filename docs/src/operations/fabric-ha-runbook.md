# Hyperledger Fabric HA Runbook (DID Registry)

## 1) Topoloji ve MSP Politikaları
- **Kurumsal Ayrım:** `Org1MSP` (kimlik doğrulama), `Org2MSP` (denetim/uyumluluk), `OrdererMSP` (konsensüs).
- **Kanal Politikaları:** `Readers` ve `Writers` yalnızca ilgili MSP üyeleriyle sınırlandırılır. `Admins` politikası için her orgdan en az bir imza zorunludur.
- **Önerilen Kanal:** `aunsorm-did` (DID registry) ve `aunsorm-audit` (audit trail).
- **Örnek Policy Baseline:** `OR('Org1MSP.admin','Org2MSP.admin')` ile güncelleme ve config değişiklikleri.

## 2) Sertifika Sağlama ve Rotasyon
- **CA Katmanı:** Kurumsal CA → ara CA → peer/orderer sertifikaları.
- **Rotasyon Sıklığı:** 90 günde bir peer/orderer sertifikaları, 180 günde bir ara CA yenilemesi.
- **Runbook Adımı:**
  1. Yeni ara CA sertifikasını üretin ve eski ara CA ile ortak zincir oluşturun.
  2. Peer/orderer TLS sertifikalarını yeni ara CA ile yeniden üretin.
  3. Rolling restart ile node’ları tek tek güncelleyin.
  4. `peer channel fetch config` + `configtxlator` ile MSP güncellemelerini kanala yayınlayın.

## 3) DID Registry Chaincode CRUD ve Erişim Kontrolü
- **CRUD İşlemleri:** `CreateDid`, `ReadDid`, `UpdateDid`, `DeleteDid` fonksiyonları.
- **Erişim Kontrolü:** `AUNSORM_FABRIC_ALLOWED_MSPS` ile MSP allowlist. Allowlist boş ise varsayılan olarak serbest erişim.
- **Event Takibi:** `did.created`, `did.updated`, `did.deleted` event’leri.
- **Kaynak:** `apps/fabric/chaincode/did_registry`.

## 4) Chaincode Lifecycle Otomasyonu
- **Script:** `scripts/fabric_chaincode_lifecycle.sh`
- **Zorunlu Env:** `FABRIC_CHANNEL`, `FABRIC_CHAINCODE`, `FABRIC_CC_VERSION`, `FABRIC_CC_SEQUENCE`.
- **Örnek Akış:**
  ```bash
  export FABRIC_CHANNEL=aunsorm-did
  export FABRIC_CHAINCODE=did-registry
  export FABRIC_CC_VERSION=1.0.0
  export FABRIC_CC_SEQUENCE=1

  ./scripts/fabric_chaincode_lifecycle.sh package
  ./scripts/fabric_chaincode_lifecycle.sh install
  ./scripts/fabric_chaincode_lifecycle.sh approve
  ./scripts/fabric_chaincode_lifecycle.sh commit
  ```

## 5) Audit Trail Pipeline (On-chain Events → Secure Log Sink)
- **Event Relay:** `apps/fabric/relay` Fabric Gateway üzerinden chaincode event’lerini dinler.
- **Sink:** `AUNSORM_AUDIT_SINK_URL` HTTP endpoint’i, JSON payload kabul eder.
- **Env Örneği:**
  ```bash
  export AUNSORM_FABRIC_GW_PEER_ENDPOINT=peer0.org1.example.com:7051
  export AUNSORM_FABRIC_GW_TLS_CERT=/var/fabric/tls/peer0.pem
  export AUNSORM_FABRIC_GW_MSP_ID=Org1MSP
  export AUNSORM_FABRIC_GW_CERT=/var/fabric/msp/signcerts/cert.pem
  export AUNSORM_FABRIC_GW_KEY=/var/fabric/msp/keystore/key.pem
  export AUNSORM_FABRIC_CHANNEL=aunsorm-did
  export AUNSORM_FABRIC_CHAINCODE=did-registry
  export AUNSORM_AUDIT_SINK_URL=https://audit.example.com/v1/events
  ```

## 6) DID Resolution Cache Policy
- **TTL:** 300 saniye (sunucu içi `FabricDidRegistry` cache).
- **Invalidation:** TTL dolumu sonrası otomatik temizlenir; DID güncellendiğinde cache yeniden doldurulur.
- **Not:** Entegrasyon için `AUNSORM_FABRIC_GATEWAY_URL` zorunlu.

## 7) HA Dağıtım Planı
- **Orderer:** RAFT 3 node (odd sayıda), `OrdererMSP` ile TLS mTLS.
- **Peer:** Her org için en az 2 peer; `peer0` anchor, `peer1` secondary.
- **Failover Testleri:**
  - `peer0` down → `peer1` event propagation doğrulaması.
  - Orderer quorum kaybı → recovery süresi ve yeni leader seçimi ölçümü.

## 8) Operasyonel Runbook
- **Deploy:** Topology → MSP → Channel → Chaincode → Event Relay → Audit Sink.
- **Upgrade:** Yeni chaincode paketi → approve → commit → relay version bump → smoke test.
- **Monitoring:** Event relay log’ları + audit sink response süreleri + Fabric peer ledger height.
