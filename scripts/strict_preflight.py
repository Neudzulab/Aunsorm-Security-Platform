#!/usr/bin/env python3
"""AUNSORM_STRICT=1 öncesi ön kontrol.

Bir .env dosyasını (ve isteğe bağlı olarak süreç ortamını) okuyup strict kipin açılışta
isteyeceği değişkenleri denetler. Değerler ASLA yazdırılmaz; yalnız ad, durum ve neden.

Kullanım:
    python3 -I scripts/strict_preflight.py path/to/.env
    python3 -I scripts/strict_preflight.py --process-env      # konteyner/CI ortamı

Çıkış kodu: 0 = engel yok, 1 = en az bir engel (FAIL), 2 = kullanım hatası.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
from urllib.parse import urlparse

# Compose dosyaları (docker/compose.zasian-stack.yaml) servis başına ayarlar; .env'de olmayabilir.
COMPOSE_PROVIDED = {"AUNSORM_LEDGER_PATH"}


def parse_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export ") :]
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key.strip()] = value
    return values


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def emit(self, level: str, name: str, reason: str) -> None:
        if level == "FAIL":
            self.failures += 1
        print(f"[{level}] {name}: {reason}")


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true"}


def falsy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"0", "false"}


def check(env: dict[str, str]) -> int:
    report = Report()
    get = lambda key: (env.get(key) or "").strip()  # noqa: E731

    if truthy(get("AUNSORM_STRICT")):
        report.emit("OK", "AUNSORM_STRICT", "etkin")
    else:
        report.emit("INFO", "AUNSORM_STRICT", "henüz etkin değil (kontrol yine de yapıldı)")

    seed = get("AUNSORM_JWT_SEED_B64")
    if not seed:
        report.emit("FAIL", "AUNSORM_JWT_SEED_B64", "tanımsız; strict açılış reddedilir")
    else:
        try:
            decoded = base64.b64decode(seed, validate=True)
        except (binascii.Error, ValueError):
            report.emit("FAIL", "AUNSORM_JWT_SEED_B64", "geçerli base64 değil")
        else:
            if len(decoded) == 32:
                report.emit("OK", "AUNSORM_JWT_SEED_B64", "32 bayt; tüm servislerde aynı olmalı")
            else:
                report.emit("FAIL", "AUNSORM_JWT_SEED_B64", f"{len(decoded)} bayt, 32 olmalı")

    if get("AUNSORM_JTI_DB") or get("AUNSORM_LEDGER_PATH"):
        report.emit("OK", "AUNSORM_JTI_DB/AUNSORM_LEDGER_PATH", "kalıcı defter yolu tanımlı")
    else:
        report.emit(
            "WARN",
            "AUNSORM_JTI_DB/AUNSORM_LEDGER_PATH",
            ".env'de yok; compose'un AUNSORM_LEDGER_PATH verdiğini doğrulayın",
        )

    internal = get("AUNSORM_INTERNAL_SECRET")
    service = get("AUNSORM_SERVICE_CLIENT_SECRET")
    if internal and len(internal) < 24:
        report.emit("FAIL", "AUNSORM_INTERNAL_SECRET", "24 karakterden kısa; sunucu yok sayar")
    if (internal and len(internal) >= 24) or service:
        report.emit("OK", "servis kimliği", "iç gizli ve/veya service-client gizli anahtarı tanımlı")
    else:
        report.emit(
            "FAIL",
            "servis kimliği",
            "AUNSORM_INTERNAL_SECRET (>=24) veya AUNSORM_SERVICE_CLIENT_SECRET gerekli; "
            "yoksa medya token/oturum çağrıları reddedilir",
        )
    if service == "aunsorm-service-secret":
        report.emit("FAIL", "AUNSORM_SERVICE_CLIENT_SECRET", "bilinen geliştirme varsayılanı")

    for key in ("AUNSORM_ROLE_BINDINGS", "AUNSORM_MFA_SECRETS"):
        raw = get(key)
        if not raw:
            report.emit("FAIL", key, "tanımsız; kullanılmıyorsa '{}' verin")
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            report.emit("FAIL", key, "geçerli JSON değil")
            continue
        if isinstance(parsed, dict):
            report.emit("OK", key, f"JSON nesnesi, {len(parsed)} kayıt")
        else:
            report.emit("FAIL", key, "JSON nesnesi olmalı")

    fingerprint = get("AUNSORM_CALIBRATION_FINGERPRINT")
    if re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
        report.emit("OK", "AUNSORM_CALIBRATION_FINGERPRINT", "64 hex")
    else:
        report.emit("FAIL", "AUNSORM_CALIBRATION_FINGERPRINT", "64 karakter hex olmalı")

    try:
        attestation = json.loads(get("AUNSORM_CLOCK_ATTESTATION") or "null")
    except json.JSONDecodeError:
        attestation = None
    if isinstance(attestation, dict) and str(attestation.get("signature_b64", "")).strip():
        report.emit("OK", "AUNSORM_CLOCK_ATTESTATION", "JSON, imza alanı dolu")
    else:
        report.emit("FAIL", "AUNSORM_CLOCK_ATTESTATION", "JSON değil ya da signature_b64 boş")

    strict_clock_raw = env.get("AUNSORM_STRICT_CLOCK")
    if falsy(strict_clock_raw):
        report.emit(
            "WARN",
            "AUNSORM_STRICT_CLOCK",
            "0: saat attestation koşulları gevşek (NTP sunucusu kurulunca kaldırın)",
        )
    else:
        url = get("AUNSORM_CLOCK_REFRESH_URL")
        if not url:
            report.emit(
                "FAIL",
                "AUNSORM_CLOCK_REFRESH_URL",
                "strict saat için zorunlu; sunucu yoksa AUNSORM_STRICT_CLOCK=0",
            )
        elif urlparse(url).scheme != "https":
            report.emit("FAIL", "AUNSORM_CLOCK_REFRESH_URL", "https olmalı")
        else:
            report.emit("OK", "AUNSORM_CLOCK_REFRESH_URL", "https")
        max_age_raw = get("AUNSORM_CLOCK_MAX_AGE_SECS") or "30"
        interval_raw = get("AUNSORM_CLOCK_REFRESH_INTERVAL_SECS") or "15"
        if max_age_raw.isdigit() and interval_raw.isdigit():
            max_age, interval = int(max_age_raw), int(interval_raw)
            if not 0 < max_age <= 30:
                report.emit("FAIL", "AUNSORM_CLOCK_MAX_AGE_SECS", "1..30 olmalı")
            elif interval > max(max_age // 2, 1):
                report.emit(
                    "FAIL",
                    "AUNSORM_CLOCK_REFRESH_INTERVAL_SECS",
                    f"en fazla {max(max_age // 2, 1)} olmalı",
                )
            else:
                report.emit("OK", "saat penceresi", f"max_age={max_age}s interval={interval}s")
        else:
            report.emit("FAIL", "saat penceresi", "sayısal olmayan değer")

    if truthy(get("AUNSORM_SERVICE_AUTH_DISABLED")):
        report.emit("WARN", "AUNSORM_SERVICE_AUTH_DISABLED", "strict kipte yok sayılır; kaldırın")
    if not get("AUNSORM_TAKEMDM_CLIENT_SECRET"):
        report.emit(
            "WARN",
            "AUNSORM_TAKEMDM_CLIENT_SECRET",
            "tanımsız; takemdm-auth public kalır ve admin rolü basabilir",
        )
    if not get("AUNSORM_ANTARYON_CLIENT_SECRET"):
        report.emit("INFO", "AUNSORM_ANTARYON_CLIENT_SECRET", "tanımsız; antaryon istemcisi kaydedilmez")

    print(f"\n{report.failures} engel bulundu." if report.failures else "\nEngel yok.")
    return 1 if report.failures else 0


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(argv) != 2 or argv[1] in {"-h", "--help"}:
        print(__doc__)
        return 2
    if argv[1] == "--process-env":
        env = dict(os.environ)
    else:
        try:
            env = parse_env_file(argv[1])
        except OSError as err:
            print(f"Dosya okunamadı: {err.strerror}")
            return 2
    for key in COMPOSE_PROVIDED:
        env.setdefault(key, "")
    return check(env)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
