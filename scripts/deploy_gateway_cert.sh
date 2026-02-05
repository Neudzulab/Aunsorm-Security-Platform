#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: deploy_gateway_cert.sh --account PATH --csr PATH --bundle PATH \
       --email EMAIL --domain DOMAIN [options]

Required arguments:
  --account PATH        ACME hesap durum dosyası (json)
  --csr PATH            Sertifika imzalama isteği (PEM veya DER)
  --bundle PATH         İndirilen sertifika zincirinin yazılacağı yol
  --email EMAIL         ACME hesabı için iletişim e-postası (tekrarlanabilir)
  --domain DOMAIN       Order içerisinde kullanılacak alan adı (tekrarlanabilir)

Optional arguments:
  --server URL          ACME sunucu taban adresi (varsayılan: http://${HOST:-localhost}:4200)
  --contact URI         ACME hesabına ek iletişim URI'sı ekle (tekrarlanabilir)
  --order-json PATH     Order yanıtının kaydedileceği dosya (varsayılan: çıktı klasörü)
  --finalize-json PATH  Finalize yanıtının kaydedileceği dosya (varsayılan: çıktı klasörü)
  --output-dir DIR      Order/finalize artefaktlarını yerleştirmek için klasör
  --cli PATH            aunsorm-cli yürütülebilirinin yolu (varsayılan: aunsorm-cli)
  --reload-cmd CMD      Sertifika başarıyla indirildikten sonra çalıştırılacak komut
  -h, --help            Bu mesajı gösterir
USAGE
}

log() {
  printf '[%s] %s\n' "$(date +%H:%M:%S)" "$1" >&2
}

ensure_parent_dir() {
  local path="$1"
  if [[ "$path" == "-" ]]; then
    return 0
  fi
  local dir
  dir=$(dirname -- "$path")
  if [[ "$dir" != "." ]]; then
    mkdir -p -- "$dir"
  fi
}

SERVER="http://${HOST:-localhost}:4200"
CLI_BIN="aunsorm-cli"
ACCOUNT=""
CSR=""
BUNDLE=""
ORDER_JSON=""
FINALIZE_JSON=""
OUTPUT_DIR=""
RELOAD_CMD=""
EMAILS=()
DOMAINS=()
CONTACTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER="$2"
      shift 2
      ;;
    --account)
      ACCOUNT="$2"
      shift 2
      ;;
    --csr)
      CSR="$2"
      shift 2
      ;;
    --bundle)
      BUNDLE="$2"
      shift 2
      ;;
    --email)
      EMAILS+=("$2")
      shift 2
      ;;
    --domain)
      DOMAINS+=("$2")
      shift 2
      ;;
    --contact)
      CONTACTS+=("$2")
      shift 2
      ;;
    --order-json)
      ORDER_JSON="$2"
      shift 2
      ;;
    --finalize-json)
      FINALIZE_JSON="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --cli)
      CLI_BIN="$2"
      shift 2
      ;;
    --reload-cmd)
      RELOAD_CMD="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n\n' "$1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ACCOUNT" || -z "$CSR" || -z "$BUNDLE" || ${#EMAILS[@]} -eq 0 || ${#DOMAINS[@]} -eq 0 ]]; then
  printf 'error: --account, --csr, --bundle, --email ve --domain parametreleri zorunludur\n\n' >&2
  usage
  exit 1
fi

if ! command -v "$CLI_BIN" >/dev/null 2>&1; then
  printf 'error: %s komutu bulunamadı\n' "$CLI_BIN" >&2
  exit 1
fi

if [[ -n "$OUTPUT_DIR" ]]; then
  mkdir -p -- "$OUTPUT_DIR"
fi

TEMP_DIR=""
if [[ -z "$OUTPUT_DIR" && ( -z "$ORDER_JSON" || -z "$FINALIZE_JSON" ) ]]; then
  TEMP_DIR=$(mktemp -d)
fi
cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

if [[ -z "$ORDER_JSON" ]]; then
  if [[ -n "$OUTPUT_DIR" ]]; then
    ORDER_JSON="$OUTPUT_DIR/order.json"
  else
    ORDER_JSON="$TEMP_DIR/order.json"
  fi
fi

if [[ -z "$FINALIZE_JSON" ]]; then
  if [[ -n "$OUTPUT_DIR" ]]; then
    FINALIZE_JSON="$OUTPUT_DIR/finalize.json"
  else
    FINALIZE_JSON="$TEMP_DIR/finalize.json"
  fi
fi

ensure_parent_dir "$ORDER_JSON"
ensure_parent_dir "$FINALIZE_JSON"
ensure_parent_dir "$BUNDLE"

register_args=("$CLI_BIN" acme register --server "$SERVER" --account "$ACCOUNT" --accept-terms)
for email in "${EMAILS[@]}"; do
  register_args+=(--email "$email")
done
for contact in "${CONTACTS[@]}"; do
  register_args+=(--contact "$contact")
done

log "ACME hesabı kaydı güncelleniyor (${ACCOUNT})"
"${register_args[@]}"

order_args=("$CLI_BIN" acme order --server "$SERVER" --account "$ACCOUNT" --output "$ORDER_JSON")
for domain in "${DOMAINS[@]}"; do
  order_args+=(--domain "$domain")
done

log "ACME order oluşturuluyor (${DOMAINS[*]})"
"${order_args[@]}"

finalize_args=("$CLI_BIN" acme finalize --server "$SERVER" --account "$ACCOUNT" --csr "$CSR" --output "$FINALIZE_JSON")

log "Order finalize ediliyor (CSR: $CSR)"
"${finalize_args[@]}"

fetch_args=("$CLI_BIN" acme fetch-cert --server "$SERVER" --account "$ACCOUNT" --output "$BUNDLE")

log "Sertifika zinciri indiriliyor ($BUNDLE)"
"${fetch_args[@]}"

if [[ -n "$RELOAD_CMD" ]]; then
  log "Yenileme komutu çalıştırılıyor: $RELOAD_CMD"
  bash -c "$RELOAD_CMD"
fi

cat <<SUMMARY
ACME sertifika dağıtımı tamamlandı.
  Account state : $ACCOUNT
  Order yanıtı  : $ORDER_JSON
  Finalize yanıt: $FINALIZE_JSON
  Sertifika     : $BUNDLE
SUMMARY
