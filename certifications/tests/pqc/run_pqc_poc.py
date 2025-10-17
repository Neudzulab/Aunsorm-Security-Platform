#!/usr/bin/env python3
"""Basit PQC PoC doğrulayıcı.

Fixture dosyalarının zorunlu alanlara sahip olduğunu ve başarı kıstaslarının
boş olmadığını kontrol eder. Gelişmiş entegrasyon testleri için altyapı sağlar.
"""
from __future__ import annotations

import json
import pathlib
import sys

REQUIRED_FIELDS = {
    "scenario",
    "nist_reference",
    "etsi_enisa_reference",
    "target_domains",
    "prerequisites",
    "flow",
    "success_criteria",
}


def validate_fixture(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        errors.append(f"{path.name}: eksik alanlar: {', '.join(sorted(missing))}")

    for field in ("target_domains", "prerequisites", "flow", "success_criteria"):
        if field in data and not data[field]:
            errors.append(f"{path.name}: '{field}' alanı boş olamaz")

    if "flow" in data:
        for index, step in enumerate(data["flow"], start=1):
            if not {"phase", "description"} <= step.keys():
                errors.append(
                    f"{path.name}: flow adımı {index} 'phase' ve 'description' alanlarını içermelidir"
                )

    return errors


def main() -> int:
    base = pathlib.Path(__file__).resolve().parent
    fixtures = sorted(base.glob("*.json"))
    if not fixtures:
        print("fixture bulunamadı", file=sys.stderr)
        return 1

    failures: list[str] = []
    for fixture in fixtures:
        failures.extend(validate_fixture(fixture))

    if failures:
        print("PQC PoC doğrulaması başarısız:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print(f"{len(fixtures)} PQC PoC fixture doğrulandı.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
