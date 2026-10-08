# Phala ACI backend trust path

```text
Hiro client
  | verifies Hiro TDX quote, measurements, provenance and KMS custody
  | attestation-bound Oak Session / Noise over WSS
  v
Hiro Proxy in a measured dstack TDX CVM
  | verifies Phala TDX quote, identity and KMS custody
  | HTTPS pinned to the SPKI declared by that verified report
  v
Phala ACI confidential inference
```

Both legs are independently bound to attestation. TLS alone is not treated as
proof that the intended workload received the request.

## Hiro identity and Oak termination

dstack KMS releases domain-separated receipt and Oak-binding keys only to the measured
Hiro workload. The public keyset, bounded expiry, service capabilities, source
provenance, and a fresh caller nonce are bound into Hiro's TDX report data.

Every inference request arrives through the Oak session. The dstack SDK supplies
keys and quotes directly. The upstream Oak implementation encrypts records; its
binding key is accepted only after the shared client verifier's full checks.
The public listener has no direct inference, ACI-v2 or legacy endpoints. Receipts
and ACI attestation mechanisms remain independent of the client transport.

## Phala verification

Before opening the listening socket, Hiro challenges the configured Phala ACI
origin at `/v1/aci/attestation` with a fresh nonce and verifies:

- DCAP/TDX evidence against PCCS collateral;
- the ACI statement and keyset binding;
- keyset expiry;
- the allowlisted measured dstack app subject;
- dstack KMS key custody against an independently pinned root;
- the TLS SPKI selected for the configured upstream origin.

Verification uses direct `aci-verify` and `dcap-qvl` calls, with an UpToDate-only
TCB policy. Cached acceptance cannot outlive keyset or collateral expiry and is
also bounded by monotonic time. A pin mismatch fails the operation; inference
is not automatically retried.

The Phala forwarder exposes only verified dispatch. A non-deserializable authority
binds the exact body, route, model and origin. Dispatch checks its freshness and
uses a Rustls client pinned to the SPKI from the accepted report. Redirects and
system proxies are disabled. DNS
compromise, a public-CA certificate, or attestation failure therefore cannot
silently downgrade the second hop.

## Receipts

Hiro hashes the exact bytes received, the plaintext forwarded after Oak
termination, and the response returned. It records the verified upstream event,
seals a content-addressed attested session, and signs the receipt with its
dstack KMS-derived Ed25519 key.

Receipts prove what the attested gateway observed; they do not make model output
truthful.

## Still separate

- Application wiring and native socket/protected-storage integration.
- Hiro authentication, entitlement, billing, usage, search,
  and attachment integration. Document conversion already has an Oak handler.
- Signed release/transparency manifests consumed by clients.
- Durable receipt/session storage when restart persistence is required.


The full `private-ai-gateway` crate is removed. Its smaller `aci-protocol` and
`aci-verify` crates are still fetched from the pinned upstream Git repository.
The proxy assembles receipts/session documents locally using the existing JCS and
receipt signing-input functions, and Ed25519 signing from `ed25519-dalek`.
