# Hiro Proxy

Hiro Proxy runs in a Phala/dstack TDX CVM. Clients use Oak Session exclusively:
upstream Noise NN P-256, attestation-bound Ed25519 handshake authentication,
and encrypted requests, uploads and response streams over WSS.

## Implemented boundary

- The official `dstack-sdk` supplies KMS keys and TDX quotes directly.
- Only two persistent keys are requested: Oak binding and receipt signing.
  Private keys stay inside the CVM; owned temporary decoded buffers are zeroized.
- The shared client verifies platform evidence, measurements, signed releases,
  KMS custody, challenge freshness and the exact Oak binding key.
- Upstream Oak establishes and encrypts sessions. There is no ACI-v2
  field-encryption endpoint, legacy signature endpoint or EHBP fallback.
- Signed receipts and cited upstream sessions use existing ACI mechanisms.
- Proxy-to-Phala inference retains independent ACI verification and SPKI-pinned TLS,
  with no unverified forwarding fallback.
- Inference and document handlers execute in-process after Oak decryption.
  The vision broker remains a separately authenticated private service.

The sibling `cypherpunk-client` supplies shared Rust code, native/WASM bindings
and the browser WSS adapter. Actual frontend wiring, native integration and
live-CVM validation remain separate launch work.

## Public endpoints

| Route | Purpose |
| --- | --- |
| `GET /health` | Process health |
| `GET /v1/session` | Oak upgrade; subprotocol `cypherpunk-session-v1` |

All other public paths are absent, including direct inference/document POSTs,
ACI/legacy attestation, receipt/session lookups and signature endpoints.
Challenge-bound evidence arrives in the Oak handshake; receipts and cited
sessions arrive in encrypted completion records. Health is not attestation.

Inside Oak, application inference uses `/v3/chat/completions` and `/v3/chat/title`.
Document conversion uses `/v1/convert/file` when configured. Generic `/v1` inference
routes are not mounted: callers cannot bypass application admission or model policy.
Sensitive headers, document metadata and bodies stay inside encryption.

## Source layout

```text
src/
  main.rs             startup, dependency assembly and listeners
  lib.rs              module declarations
  config.rs           configuration parsing and validation
  transport/          Oak sessions and binary WSS carrier
  attestation/        dstack keys, evidence and upstream verification
  auth/               JWT verification, user extraction and request authentication
  inference/          provider transport, SSE decoding, validation, limits and usage
  api/                HTTP route handlers and internal routers
  services/           document and inference operations
  storage/            quota reads and bounded completion-proof/session caches
```

Application handlers are mounted behind the Oak dispatcher. The document vision
broker has its own authenticated private router. Existing PostgreSQL entitlement
and quota reads live in `storage/quota.rs`; object storage is a later port.

## Application inference

See [the inference contract](docs/INFERENCE.md) for models, limits, streaming,
receipts, accounting, configuration and the browser SDK call contract.

## Configuration

Every decrypted application request passes through `auth::protect` before its
handler. It preserves the old backend's RS256 bearer-token contract: issuer,
authorized party (`azp`), subject, expiry, not-before, optional audience, and
five-second clock leeway. Handlers can extract `auth::User` and call `id()`.
The public health/handshake endpoints remain separate; the private vision broker
retains its service credential. User tokens stay inside Oak and are not forwarded
to the inference provider.

Authentication configuration uses the existing names:

| Variable | Meaning |
| --- | --- |
| `AUTH_ISSUER` | Required HTTPS token issuer |
| `AUTH_AUTHORIZED_PARTIES` | Required comma-separated allowed `azp` values |
| `AUTH_JWT_KEY` | Optional RSA verification PEM, including escaped newlines |
| `AUTH_JWKS_URL` | HTTPS JWKS endpoint; defaults to the issuer's `/.well-known/jwks.json` |
| `AUTH_AUDIENCE` | Optional required token audience |
| `AUTH_JWKS_CACHE_SECONDS` | Cache lifetime, default 3600, range 1–86400 |

Without a PEM, keys are refreshed from JWKS with timeouts, a 1 MiB streamed
response limit, a 128-key limit, and five-second refresh throttling. Expired
cached keys cannot authorize a request. Redirects and system proxies are disabled.
Invalid tokens produce status 401; unavailable verification keys produce 503.
These statuses and redacted error bodies travel inside Oak, followed by its
authenticated `request_rejected` terminal record. The SDK treats completion as
failed; no inference receipt is fabricated for a rejected request.

Required configuration includes `DSTACK_ENDPOINT`, `PHALA_ACI_BASE_URL`,
`PHALA_API_KEY`, `PHALA_ACI_ACCEPTED_SUBJECTS`,
`PHALA_ACI_ACCEPTED_KMS_ROOT_KEYS`, `HIRO_SOURCE_REPOSITORY`,
`HIRO_SOURCE_COMMIT`, and `HIRO_OAK_EVIDENCE_PATH`.
See `src/config.rs` for validation. The dstack socket is normally
`/var/run/dstack.sock`. Serve `/v1/session` over WSS using the CVM ingress.

`HIRO_OAK_EVIDENCE_PATH` names a public JSON artifact with exactly `schema: 1`,
`collateral`, `release`, `policy`, and `kms`, shaped according to the client
verifier contract. The proxy adds a fresh challenge-bound report per handshake.
Supply real collateral and signed release/policy artifacts; refresh atomically.
Clients independently authenticate them against locally provisioned trust.

| Key role | dstack path | Purpose |
| --- | --- | --- |
| Receipt | `aci/receipt-ed25519/v1` | `aci.receipt.ed25519.v1` |
| Oak binding | `oak/session-binding-ed25519/v1` | `oak.session.binding.ed25519.v1` |

The receipt purpose preserves the established receipt contract. It does not
enable ACI transport encryption.

## Dependencies and build

`src/attestation/keys.rs` adapts the unmodified official dstack SDK. Oak cryptography
comes from the pinned upstream source in the sibling client workspace.

The full `private-ai-gateway` crate is not a dependency. No gateway source is
vendored or patched. The proxy uses these libraries directly:

- `dstack-sdk`: workload keys and quotes.
- `aci-protocol`: existing wire types, JCS, report binding and receipt signing input.
- `aci-verify`: report binding, dstack measurements/KMS custody and TLS-key selection.
- `dcap-qvl`: Intel-rooted TDX verification with explicit policy appraisal.
- Rustls/Reqwest: HTTPS pinned to the attested SPKI, with redirects and proxies disabled.
- Oak Session: client-facing encrypted transport.

`aci-protocol` and `aci-verify` are smaller crates published in the same upstream
Git repository; Cargo still fetches that repository at the pinned revision. This
is not a dependency on the gateway application crate.

`src/attestation/upstream.rs` owns upstream acceptance and bounded verification caching;
`src/inference/upstream.rs` dispatches only with a fresh request-bound verification result;
`src/inference/tls.rs` enforces the attested key and TLS handshake signatures;
`src/attestation/evidence.rs` assembles compatible session documents and signed receipts.
`src/api/inference.rs` owns in-process routing; `src/services/inference.rs`
coordinates verified responses; `src/storage/completions.rs` owns bounded proof/session storage.

Building needs this source tree, the sibling client transport/vendor tree,
the pinned Git dependencies and `protoc`. Container/deployment packaging is deferred;
existing deployment files are templates, not a completed release.

## Validation and launch work

The proxy migration is checked with `cargo check`. Tests and lints are not run.
Compilation is not runtime security validation. The shared client source is unchanged.

Before launch: complete application wiring, native adapters, genuine-CVM and
failure-path interoperability, independent review, and release infrastructure.
Reviewed source, provenance, digest-pinned measured composition and signed
release/policy artifacts must be delivered through that release infrastructure.

The exact wire contract and limits are in
[transport/PROTOCOL.md](../cypherpunk-client/crates/transport/PROTOCOL.md).

## License

GNU Affero General Public License v3.0 only. Vendored dependencies retain their
own licenses.

## Direct-library migration — 2026-10-08

The full gateway crate and its application wrappers are removed. The Oak wire
protocol, dstack key paths, public routes, ACI report format and receipt/session
format remain compatible with the existing client. The upstream verifier label
is now `phala-tdx/v1`; it is diagnostic, not a client trust anchor.

Each upstream forwarding authority binds the origin, route, model and exact
request body hash. Its expiry is bounded by the cache TTL, attested keyset expiry,
collateral expiry, and monotonic time. The verifier requires an UpToDate TCB with
no grace period; debug and service-TD quotes are rejected by QVL defaults. SMT,
dynamic-platform and cached-key configurations remain permitted, as in the prior
upstream verifier. Only independently configured measured app IDs and KMS roots
are accepted. A configured PCCS endpoint must use HTTPS.

Response bytes are hashed incrementally; cancelled, failed or dropped response
streams do not publish a completion receipt. Completed proofs are single-use,
retained for at most 60 seconds, and bounded to 32 entries. Session records are
also bounded to 32 unexpired entries and never outlive upstream verification.
No inference request is retried automatically.

This change replaces the dependency integration. It does not implement account
entitlements, identity renewal, deployment packaging or provider-specific SSE
terminal-event validation. A receipt authenticates the returned bytes; HTTP EOF
alone does not establish successful model generation. Live-CVM interoperability
remains a deployment validation requirement.
