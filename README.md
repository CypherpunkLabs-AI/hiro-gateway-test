# Hiro Proxy

Confidential application gateway for an Intel TDX guest on GCP. The container runs as UID/GID 65532, listens on port 8080, and uses Oak Session to encrypt application traffic end to end. Confidential Space is not used.

The proxy generates independent ephemeral Ed25519 keys for Oak session binding and completion receipts. Keys remain in guest memory and change on process restart. There is no local KMS, dstack socket, evidence worker or persistent key volume. The separate Phala inference service is still verified using DCAP, its approved ACI identity and attested TLS public key before requests are forwarded.

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | Process liveness; works without database/inference connectivity |
| `GET /ready` | Can produce fresh, release-bound TDX evidence |
| `GET /v1/attestation?nonce=<64 lowercase hex characters>` | Public challenge-bound ACI evidence, with `Cache-Control: no-store` |
| `GET /v1/session` | Oak carrier; WebSocket subprotocol `cypherpunk-session-v1` |

Application routes are accessible only inside Oak. Missing hardware, an unmeasured release or failed upstream verification never enables plaintext or unverified forwarding. `.env.example` contains public dummy values that allow the process to boot; application requests cannot succeed with them.

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
