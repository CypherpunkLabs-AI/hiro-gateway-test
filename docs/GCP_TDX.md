# GCP TDX runtime and evidence contract

Profile: `hiro.gcp-tdx.v1`. Architecture: Linux amd64. Container identity: UID/GID 65532. The measured guest OS and launcher, including their boot policy, are part of the client-approved trusted computing base. This container does not build or provision that OS.

## Guest inputs

The launcher provisions one Linux configfs TSM report entry at `/sys/kernel/config/tsm/report/hiro-proxy` and mounts that entry at `/run/hiro/tdx-report`. The provider must be `tdx_guest`. Delegate only the entry's `inblob` write and `outblob`, `provider`, `generation` read access to UID 65532. No privileged container, full configfs mount or dstack daemon is required. The proxy serializes quote requests, checks the generation counter and requires the returned REPORTDATA to match its request.

Mount `/run/hiro/attestation` read-only with:

- `ccel.bin`: the guest's raw CCEL boot event log, copied from `/sys/firmware/acpi/tables/data/CCEL` by the measured launcher.
- `release.json`: the exact signed release bytes assembled by `hiro`.

The launcher verifies the release signature against its approved publisher policy, verifies the exact Compose SHA-256 and OCI digest pins, and enforces the approved launch configuration. Before starting the container, it extends an initially zero RTMR3 once with `SHA384("hiro.release.v1\0" || release_json_bytes)`. The resulting register must equal `SHA384(zero_48_bytes || event_digest)`. The NUL is one zero byte. No other component may use RTMR3 under this profile. The proxy rejects quotes that do not contain that exact value.

The release JSON contains `schema: 1`, `profile: "hiro.gcp-tdx.v1"`, `compose_sha256` as 64 lowercase hex characters, and `containers` mapping service names, including `hiro-proxy`, to `registry/repository@sha256:<64 lowercase hex>`. Whitespace in the signed JSON is significant: never reserialize it after signing or measurement.

The guest must enforce its approved immutable root filesystem/boot policy, disable administrative plaintext access, swap and core dumps, and control writable mounts and launch configuration. TDX alone does not enforce those software policies. Merely extending a digest from an ordinary administrator-controlled VM does not prove those policies.

## Evidence and channel binding

The client supplies 32 random challenge bytes. For the public HTTP endpoint they are lowercase hex. For Oak, the initial binary record is `CPK1` followed by those bytes. The ACI `attestation_statement(keyset_digest, nonce)` and `report_data` encoding is retained; its 32-byte digest is padded with 32 zero bytes into TDX REPORTDATA.

The ACI report's evidence includes `profile`, raw hex `quote`, hex `quote_report_data`, hex `ccel`, the exact UTF-8 `release_manifest`, and the release measurement descriptor. The Oak assertion ID is `hiro.gcp-tdx.v1`; the binding algorithm remains `oak-session-v1-ed25519`. The attested binding key signs Oak's handshake token followed by `cypherpunk.oak-session.v1`, preventing an intermediary from substituting its own encrypted channel.

The client independently verifies Intel's DCAP signature/certificate chain and current collateral, TCB/revocation/debug policy, approved boot measurements and replayed CCEL, the signed release and its approval/rollback policy, the exact RTMR3 extension, its fresh challenge and keyset digest, and the Oak handshake binding. It must not trust the server's source-provenance strings or measurement descriptor as an approval. Quote collection inside the proxy is not a substitute for client verification. Signed release assets are public in GitHub; Intel collateral can be obtained independently. No evidence worker is needed for those client checks.

## Keys and application dependencies

Receipt and Oak binding keys are generated independently using guest OS randomness. They are never persisted or returned as private material. Their temporary seeds are zeroized; signing keys use the library's zeroization support. They rotate on process restart. Each TLS connection receives a keyset valid for at most `HIRO_KEYSET_TTL_SECONDS` (default 30 days), capped by the selected certificate's expiration. New connections receive fresh keysets; expired identities cannot attest or authorize new inference requests.

HTTPS/WSS terminates inside this proxy using Rustls TLS 1.3 on container port 8443, published as guest TCP 443. ACME TLS-ALPN-01 obtains and renews an ECDSA P-256 certificate for the measured `HIRO_TLS_DOMAIN`. Its key is independent of the Oak and receipt keys. `/run/hiro/tls` must be a private tmpfs owned by UID/GID 65532 with mode `0700` and `noswap`; cache files are `0600`. ACME state survives container restart but not VM restart. TLS early data, resumption, key logging and secret extraction are disabled. No plaintext or self-signed fallback is available if issuance fails.

The selected certificate's DER SubjectPublicKeyInfo SHA-256 and domain populate `tls_public_keys`. The same immutable per-connection keyset is used in public evidence, the Oak handshake and completion receipts. Certificate renewal cannot replace the keyset of an existing connection. Native clients can compare the TLS certificate SPKI with this attested entry; browser clients use the browser's certificate verification and independently verify the attested Oak handshake. A load balancer may forward TCP, but must not terminate TLS in this deployment.

Database initialization is lazy. Health and attestation do not depend on database or inference connectivity. Authentication, quota admission and remote inference verification still fail closed on requests. The remote Phala KMS root setting authenticates the inference provider only; it does not release local proxy keys.

Optional document services communicate over `DOCUMENT_ROUTER_SOCKET` and `DOCUMENT_VISION_SOCKET` Unix sockets. Include every plaintext-handling document service in the measured release and keep both sockets inside the approved guest. The vision broker also requires its existing shared token and approved model.
