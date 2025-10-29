#!/usr/bin/env bash
set -euo pipefail

ORDER_ID=${AUNSORM_ACME_ORDER:-unknown}
FULLCHAIN=${AUNSORM_ACME_FULLCHAIN:-}
PRIVKEY=${AUNSORM_ACME_PRIVATE_KEY:-}

echo "[acme-hooks] Yenilenen sertifika: ${ORDER_ID}"
if [[ -n "${FULLCHAIN}" ]]; then
    echo "[acme-hooks] Fullchain konumu: ${FULLCHAIN}"
fi
if [[ -n "${PRIVKEY}" ]]; then
    echo "[acme-hooks] Özel anahtar konumu: ${PRIVKEY}"
fi

echo "[acme-hooks] Nginx yeniden yükleme simülasyonu"
# Gerçek ortamda aşağıdaki satırı etkinleştirin:
# systemctl reload nginx

echo "[acme-hooks] İşlem tamamlandı"
