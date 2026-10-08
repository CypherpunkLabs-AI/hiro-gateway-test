# Security architecture

## Trust chain

Reviewed source -> digest-pinned measured composition -> dstack TDX evidence ->
independent client release/platform/custody verification -> Oak handshake binding ->
encrypted application records.

Phala/dstack supplies evidence and workload-derived keys. Application acceptance
belongs to the client's independently provisioned policy. Phala does not require
the gateway library or ACI client field encryption.

## Keys and startup

The proxy calls the official dstack SDK directly for two domain-separated keys:
Ed25519 receipt signing and Ed25519 Oak handshake binding. dstack supplies their
derivation chains. Its secp256k1 counterpart authenticates the seed's KMS origin;
approved measured workload code establishes the Ed25519 conversion.

The proxy rejects missing custody chains, malformed keys and reuse between roles.
Key seeds are not logged or sent upstream; owned temporary buffers are zeroized.
Oak generates separate ephemeral P-256 secrets using its existing implementation.

Hiro seals exactly one Oak binding key and one distinct receipt key supplied
by its validated concrete dstack adapter. It advertises no ACI E2EE version and
publishes no service TLS key. Keyset canonicalization comes directly from `aci-protocol`. The full gateway
crate is absent; no local gateway copy or dependency patch remains. No ACI
encryption key is provisioned.

Before listening the proxy independently verifies Phala's inference endpoint and
obtains an enforceable attested TLS SPKI binding.

## Attestation and transport

The fresh client challenge is carried in Oak initialization. The existing ACI
statement and JCS keyset encoding produce the report-data sent to dstack's quote
API. The statement digest occupies bytes 0-31; bytes 32-63 are zero. The adapter
checks that dstack returned exactly the requested report data.

The bound assertion contains the report, collateral, signed release/policy and
KMS evidence. Client verification and durable rollback-state adoption precede
acceptance of Oak's handshake binding. Noise NN alone is not authentication.
No private request can be sent before both stages succeed.

Only `/health` and `/v1/session` are public. Sensitive headers, request bodies,
filenames, responses, receipts and cited sessions travel inside Oak. In-process
inference/document dispatch is gated by the shared method/path/header allowlist.
There is no gateway application router dependency.

Ordered encrypted records, request identifiers, body digests, credit, terminal
acknowledgements, expiry, cancellation and receipt/session checks enforce the
specified lifecycle. Incomplete responses remain incomplete; failed requests are
not automatically retried. Exact limits are in the sibling transport protocol.

## Verified inference connection

The proxy verifies Phala's ACI evidence, accepted measured identity, KMS custody
and TLS SPKI. The local forwarding adapter uses Rustls to pin its TLS connection to that accepted SPKI
and offers no unverified forwarding fallback. Signed receipts commit to exact
request/response bytes and the cited upstream session.

ACI attestation and receipt formats remain; ACI client field encryption does not.
The client authenticates the attested proxy's commitments rather than independently
reverifying every downstream worker.

## Remaining launch work

Actual application wiring, native socket/protected-storage integration,
genuine-CVM and failure-path interoperability, independent review, and signed
release/container deployment infrastructure remain outstanding. Existing
passkey/PRF storage formats are unchanged. Compilation does not establish
runtime interoperability or an audited security level.

The inference connection is documented in
[PHALA_ACI_BACKEND.md](PHALA_ACI_BACKEND.md).

Hiro owns routing in `src/api/`, stream/receipt coordination in
`src/services/inference.rs`, and bounded proof/session caches in `src/storage/completions.rs`.
`aci-protocol` and `aci-verify` supply protocol and verification mechanisms directly;
`dcap-qvl` verifies hardware evidence; Rustls verifies TLS handshake signatures.
The smaller ACI crates remain pinned to their upstream Git repository, but the
`private-ai-gateway` application crate is no longer in the dependency graph. Receipt proofs are consumed once and expire
within 60 seconds; proof/session collections each admit at most 32 entries.
Upstream failure, stream error and cancellation do not produce successful Oak
completion. Requests are not automatically retried.


## Upstream authorization boundary

Only `src/attestation/upstream.rs` can construct the non-deserializable forwarding authority.
It binds the exact body hash, route, model and origin to the accepted report.
`src/inference/upstream.rs` checks that authority immediately before sending, and creates a
Rustls client accepting only its attested SPKI at its verified host. TLS handshake
signatures still prove key possession; a public CA certificate alone cannot pass.
Self-signed certificates with the attested key remain supported. Redirects,
system proxies and automatic inference retries are disabled.

The upstream policy requires UpToDate TCB with current collateral and rejects
debug/service-TD quotes. It retains acceptance of SMT, dynamic platforms and
cached keys; these are not independently pinned platform profiles. Event-log
replay, measured compose preimage, measured app-ID allowlist and pinned KMS root
checks precede TLS-pin acceptance. No image-provenance self-assertion substitutes
for the measured app ID.

Cached evidence expires at the earliest of cache TTL, keyset expiry and collateral
expiry, with an additional monotonic deadline. Session documents cannot outlive
that authority. No stale verification is reused after a failed refresh.

Bearer authentication now runs on all decrypted application routes via
`auth::protect`, using the existing RS256 issuer/azp/subject/time/audience checks.
Only this middleware creates the `User` extension consumed by handlers. Key
retrieval failure fails closed. Auth failures end with an encrypted rejection,
never a successful inference completion. Chat and title routes enforce existing
PostgreSQL entitlements/quotas, a shared per-account request limiter, concurrency
and usage-queue admission. Stripe integration and identity renewal remain separate work.
Application receipts cover the exact received request, transformed provider request
and emitted SSE/JSON bytes. Successful inference requires valid OpenAI SSE, a finish
reason, usage and `[DONE]`; HTTP EOF alone cannot produce a successful receipt.
See [the application contract](INFERENCE.md).
