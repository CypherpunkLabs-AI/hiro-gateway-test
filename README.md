# Hiro Proxy

Confidential application gateway for an Intel TDX guest on GCP. The container runs as UID/GID 65532, terminates TLS 1.3 on port 8443, and uses Oak Session to encrypt application traffic end to end. Hiro publishes this listener as TCP 443. Confidential Space is not used.

The proxy generates independent ephemeral Ed25519 keys for Oak session binding and completion receipts. Keys remain in guest memory and change on process restart. Separate ECDSA P-256 TLS keys and ACME account state are generated inside the guest and cached only in its private, non-swappable tmpfs. There is no local KMS, dstack socket, evidence worker or persistent key volume. The separate Phala inference service is still verified using DCAP, its approved ACI identity and attested TLS public key before requests are forwarded.

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | Process liveness; works without database/inference connectivity |
| `GET /ready` | Can produce fresh, release-bound TDX evidence |
| `GET /v1/attestation?nonce=<64 lowercase hex characters>` | Public challenge-bound ACI evidence, with `Cache-Control: no-store` |
| `GET /v1/session` | Oak carrier; WebSocket subprotocol `cypherpunk-session-v1` |

Application routes are accessible only inside Oak. Missing hardware, an unmeasured release or failed upstream verification never enables plaintext or unverified forwarding. `.env.example` contains public dummy values that allow the process to boot; application requests cannot succeed with them.

All public endpoints require HTTPS/WSS and an issued certificate. `HIRO_TLS_DOMAIN` selects the hostname; the Hiro release pins `api.cypherpunklabs.io`. Point DNS directly at the VM and allow inbound TCP 443 and outbound HTTPS for ACME. Use DNS-only mode for any CDN DNS record, or a TCP passthrough load balancer; external TLS termination is incompatible with this deployment. `HIRO_ACME_ENVIRONMENT` accepts `production` or `staging` (staging certificates are not browser-trusted).

The embedded `rustls-acme` client handles TLS-ALPN-01, renewal and issuance backoff. Until it has a valid certificate, the listener fails closed; there is no self-signed or HTTP fallback. TLS 1.2, early data/0-RTT, TLS key logging, secret extraction and session resumption are disabled. Certificate replacement affects new connections; each existing connection retains its attested TLS keyset and receipt identity until expiration. ACME dependency response logging is suppressed.

Mount `/run/hiro/tls` as a dedicated `tmpfs` with `noswap,nosuid,nodev,noexec,mode=0700,uid=65532,gid=65532`; cache files use `0600`. The proxy rejects disk-backed cache storage and enabled swap. This mount survives container restarts, but VM restart destroys it and requires certificate reissuance. Never copy TLS keys to `secrets.env`, an image, or a persistent volume. Full-VM restart frequency remains subject to the CA's issuance limits.

## Runtime integration

[docs/GCP_TDX.md](docs/GCP_TDX.md) defines the guest mounts, exact release measurement and client verification contract. The `hiro` repository assembles the Compose release. This repository builds only the proxy container. Optional document conversion uses Unix sockets within the same measured guest; no remote plaintext document URL is supported.

The existing client must implement the `hiro.gcp-tdx.v1` assertion profile before sending application data. Public evidence is input to verification, never an assertion that verification has succeeded.

## Build and publication

```sh
bash scripts/install-bazel /tmp/hiro-bin
/tmp/hiro-bin/bazel test --lockfile_mode=error --@rules_rust//:clippy_flag=-Dwarnings //:hiro-proxy //:format //:clippy //:hiro_proxy_tests //:hiro_proxy_bin_tests
docker build -t hiro-proxy:local .
```

Pushing `main` publishes `ghcr.io/<GitHub repository>` with source-SHA and build tags. Pushing a version such as `v0.1.0` also publishes that version tag and a GitHub release. CI produces and verifies GitHub/Sigstore build provenance for the OCI digest, signs `images.lock.json`, and publishes the lock, verification bundles and exact `image@sha256:...` reference. Tags are discovery names; `hiro` consumes the immutable digest.

In the `hiro` repository, run `scripts/import-proxy-image --release v0.1.0` or `scripts/import-proxy-image --run <successful-main-CI-run>`. The importer verifies metadata and OCI provenance, including the repository, workflow revision, source commit and ref. The actual remote for this checkout is `CypherpunkLabs-AI/hiro-gateway-test`; publication derives its name from GitHub rather than hard-coding another repository.
