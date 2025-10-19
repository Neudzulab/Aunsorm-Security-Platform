#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

run() {
  echo "\n==> $*"
  (cd "$ROOT_DIR" && eval "$@")
}

run "cargo bench -p interop-benches --bench aead -- --quick"
run "cargo bench -p interop-benches --bench session -- --quick"
run "cargo bench -p interop-benches --bench x509 -- --quick"
run "cargo +nightly fuzz run fuzz_packet -- -runs=10000 -detect_leaks=0 -verbosity=0 -print_final_stats=1"
run "cargo +nightly fuzz run fuzz_session -- -runs=10000 -detect_leaks=0 -verbosity=0 -print_final_stats=1"
run "cargo test -p aunsorm-pytests"
