# Release Checklist

- [ ] All crates build successfully (`cargo build --workspace`).
- [ ] All services start via Docker Compose with health checks passing.
- [ ] All automated tests succeed (`cargo test --workspace`).
- [ ] Documentation updated (`README.md`, `docs/architecture/`, `docs/security/`, `docs/deployment/`, `docs/api/`).
- [ ] No sensitive or private information present in repository or `.env` values.
- [ ] Port map aligns with `port-map.yaml` and `.env.example`.
- [ ] Calibration fingerprints and RNG configuration validated against production authorities.
- [ ] CHANGELOG updated with the targeted version.
