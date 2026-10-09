# Supporting evidence and startup

The same proxy executable has two commands:

```sh
hiro-proxy serve
hiro-proxy evidence
```

The default command remains `serve`. The worker initializes neither application
configuration nor authentication, database, inference or dstack key clients. Only
the proxy receives application credentials and the dstack socket.

## Process interface

The proxy opens the Unix socket configured by `HIRO_EVIDENCE_SOCKET` after creating
its attested identity, before contacting the inference provider or database. It
does not require an evidence file to open this socket. Provision the parent
directory with an owner/group permitting only the proxy and worker to connect.
The parent directory must exclude access by other users (`0770` or `0700`).
The proxy creates the socket with mode `0660`; do not publish it over TCP.

- `GET /health`: bootstrap listener liveness.
- `GET /v1/report?nonce=<64 lowercase hex characters>`: the proxy's public
  challenge-bound attestation report, including its quote, event log, composition,
  public key descriptors and custody signatures.

The interface does not expose `GetKey`, raw arbitrary report-data quoting,
application requests, tokens, private signing keys, or upstream credentials. One
quote request can run at a time and has a 20-second timeout. The worker has no
reason to mount `/var/run/dstack.sock`.

The public server exposes `/health` for liveness and `/ready` for verified-evidence
readiness. `/v1/session` returns 503 before readiness. It also rechecks evidence
after quote acquisition and after completing the Oak handshake. Application
dependency initialization must succeed before the public listener opens.

## Configuration

Both processes require these public configuration inputs:

| Variable | Meaning |
| --- | --- |
| `HIRO_EVIDENCE_SOCKET` | Absolute shared Unix socket path. |
| `HIRO_OAK_EVIDENCE_PATH` | Absolute shared snapshot path, normally `/run/hiro/evidence/evidence.json`. |
| `HIRO_TRUST_CONFIG_PATH` | Read-only, independently provisioned SDK `TrustConfig` JSON. |
| `HIRO_SIGSTORE_ROOTS_PATH` | Read-only Sigstore trust-root JSON matching the digest in `TrustConfig`. |
| `HIRO_EVIDENCE_STATE_DIR` | Private writable persistent directory; **different volumes for proxy and worker**. |

Only the worker reads:

| Variable | Meaning |
| --- | --- |
| `HIRO_RELEASE_BASE_URL` | HTTPS directory ending in `/`; releases are fetched as `<compose-sha256>.json`. |
| `HIRO_POLICY_URL` | HTTPS URL of the current signed policy wrapper. |
| `HIRO_KMS_EVIDENCE_URL` | HTTPS URL of the public KMS evidence document described below. |
| `HIRO_PCCS_URL` | Explicit HTTPS PCCS endpoint for both workload and KMS quote collateral. |

Worker artifact requests reject redirects, limit responses to 4 MiB, and have
connection/request timeouts. QVL collateral retrieval uses the same bounded HTTP
adapter. URLs containing embedded username/password credentials are rejected.
Errors are logged without evidence payloads or source URLs.

The deployment supplies these actual public artifact locations. Trust files are
provisioned independently and are never downloaded from the evidence source.

## Artifact contracts

Release and policy endpoints return the existing SDK wrapper:

```json
{"artifact":"<exact signed JSON bytes as a string>","bundle":"<Sigstore bundle JSON as a string>"}
```

The KMS endpoint returns the SDK's existing `KmsEvidence` shape:

```text
quote                 hex-encoded KMS bootstrap TDX quote
event_log             JSON event-log string
app_compose           exact KMS application-composition JSON string
ca_public_key         hex-encoded CA SubjectPublicKeyInfo bytes
root_public_key       compressed secp256k1 public key, hex encoded
collateral            optional on download; worker replaces it with fetched collateral
```

This endpoint distributes public evidence; it does not gain authority by serving
it. The proxy verification module authenticates the bootstrap quote, its public-key binding,
event-log replay, measured composition and approved KMS identity. Invalid, missing,
unsupported or mismatched evidence cannot produce a published snapshot.

`HIRO_KMS_EVIDENCE_URL` is **not** a raw `KMS.GetMeta` URL. Raw GetMeta contains an
encoded bootstrap attestation and does not directly satisfy the SDK's normalized
document contract. Provisioning must supply this public document with its exact
KMS composition preimage. This command consumes that document; it does not create
or operate a KMS, synthesize bootstrap evidence, or add another evidence wire format.

## Verification, persistence and refresh

1. Download and authenticate the signed policy with the proxy-local `src/attestation/verification` module.
2. Persist its rollback checkpoint and atomically publish `policy.json` alongside
   the snapshot before retrieving other inputs. A revocation survives a subsequent
   network or recipient-verification failure.
3. Obtain the local report through the Unix socket and hash its exact composition.
   Fetch the corresponding signed release and KMS document, and fetch both sets of
   collateral through `dcap-qvl`.
4. Generate a new verifier challenge and request a fresh local report. Fully verify
   the assembled document with the proxy verification module, including measurements, signed
   release approval, KMS custody and key binding. Durably acknowledge its checkpoint.
5. Write the supporting five-field snapshot to a same-directory temporary file,
   fsync it, rename it atomically and fsync the directory. Readers never see half
   of a snapshot. The proxy generates fresh reports for actual client challenges.
6. Refresh before the verifier's acceptance deadline, with bounded retry backoff
   and jitter. Failed attempts leave the previous snapshot untouched. The worker's
   private `status.json` reports the last successful acceptance expiry.

The proxy separately verifies the file with its own verification state, fresh local
challenge and persistent checkpoint. It retains an in-memory snapshot only until
the verified wall-clock and monotonic deadlines. A newly authenticated policy
invalidates previous acceptance before replacement evidence is appraised; failed
refreshes cannot hide revocation or renew expiry. Missing or invalid files never
make an unready proxy ready. Expiry closes admission to new Oak sessions.

Both state directories use exclusive process locks and atomic checkpoint writes.
Preserve these volumes across restarts; deleting them discards locally observed
rollback floors. Worker-written status and expiry values are never proxy authority.

## Compose integration

Use the same immutable image digest with commands `serve` and `evidence`. Provide
the worker a read-only mount of the bootstrap socket directory, a writable evidence
volume and its own state volume. The proxy owns the socket directory, reads the
evidence volume, and writes only its own state volume. Mount trust configuration
read-only in both containers. Restrict directory ownership to their runtime users.

Start the proxy and worker independently. Do not make proxy process startup depend
on worker readiness: the worker needs the proxy's bootstrap interface. Route private
traffic only after the proxy's public `/ready` succeeds. Monitor worker refresh
failures separately; a worker restart alone does not require a proxy restart.
`hiro-proxy evidence-health` checks the worker's private status file and its expiry
for a container health check. SIGTERM and SIGINT stop the worker during either
retrieval or retry sleep, marking it unready without deleting the last snapshot.

Live acceptance still requires published signed artifacts, actual platform/KMS
configuration and a Phala CVM. A local compile or configuration check does not
substitute for an SDK connection to that deployment.
