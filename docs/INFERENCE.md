# Application inference

`api/inference.rs` mounts `/v3/chat/completions` and `/v3/chat/title` inside
JWT-authenticated Oak sessions. `services/chat.rs` owns application policy;
`services/inference.rs` owns Phala verification and signed receipts. Every provider
call passes through `InferenceVerifier` and `InferenceBackend`'s attested
SPKI-pinned TLS. There is no ordinary HTTPS, Tinfoil or EHBP inference fallback.
Generic `/v1` inference routes are not mounted for clients: they cannot bypass
model access, system prompts, quotas or accounting. The provider endpoint is
`/v1/chat/completions`.

## Models and requests

| Purpose | Model |
| --- | --- |
| Default chat, all plans | `z-ai/glm-5.3-flash` |
| Pro chat | `moonshotai/kimi-k3` |
| Chat title | `z-ai/glm-5.3-flash` |

Chat accepts `{request_id, messages, model?, web_search?, user_cache_secret?}`.
`request_id` is a UUID. The previous `user_cache_secret` input remains accepted
but ignored. Omitted/empty model selects GLM; free accounts requesting Kimi fall
back to GLM, preserving existing behavior. Other IDs are rejected. The server
prepends `INFERENCE_SYSTEM_PROMPT` and controls temperature/output limits.
Unknown fields, system roles and caller-supplied generation controls are rejected.

Validation preserves 1–128 messages, 1–64 parts per multipart message, 20 MiB text,
at most 20 images totaling 20 MiB decoded, and inline base64 JPEG/PNG/WebP/GIF only.
Assistant images and remote image URLs are rejected. Multipart content requires
Pro. The request envelope is capped at 64 MiB. This validates input format;
selected provider models still determine supported modalities.

Title accepts `{request_id, message}` with 1–12,000 bytes of trimmed message.
It uses the existing dedicated instruction, temperature 0.2 and 64 output tokens.
The `{title}` result is whitespace-normalized, stripped of quotes, labels and
trailing punctuation, and capped at 50 characters. Empty output fails.

Both routes share the existing 20 requests/minute, burst-5 per-account limiter,
quota enforcement and concurrency semaphore. `storage/quota.rs` preserves the
existing `stripe_subscriptions` entitlement query and
`usage_quota_state.blocked_until` contract. Database failure denies admission.
Inference makes no Stripe API calls or subscription/customer mutations.

## Streaming and receipts

Provider requests use OpenAI streaming with `stream_options.include_usage=true`.
`eventsource-stream` handles SSE framing and fragmented UTF-8. The decoder requires
a successful HTTP status, SSE content type, valid JSON/choice structure, finish
reason, nonnegative consistent usage and `[DONE]`. Total provider output is bounded
to 64 MiB. Provider errors and premature EOF fail the operation.

Chat preserves SSE `chunk`, `error`, `done`, and 15-second keepalives. An interrupted
stream produces no successful `done` or receipt. Oak cancellation drops upstream
I/O and releases the concurrency permit. Inference is not automatically retried.

Receipts bind the original request, transformed provider request, and exact
emitted SSE/JSON bytes, including keepalives. Top-level `model` records the
requested model; `upstream.verified.model_id` records the actual selected model.
For title, top-level model is null and upstream model is GLM. Receipt publication
requires clean completion of the application response, after validating the
provider's terminal event and usage. Rejections carry redacted status/error bodies
and Oak's authenticated failure terminal, without a fabricated inference receipt.

## Browser SDK contract

Use the existing SDK option `allowRequestRewrite: true` for both application
routes: the server adds system prompts and generation controls. This does not
skip receipt signatures, request/response hashes or upstream/session checks.
The browser SDK requires an explicit full model ID for chat; title has no model
override.

```ts
const response = await client.fetch('/v3/chat/completions', {
  method: 'POST',
  headers: {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  },
  allowRequestRewrite: true,
  body: JSON.stringify({
    request_id: crypto.randomUUID(),
    model: 'z-ai/glm-5.3-flash',
    messages: [{ role: 'user', content: 'Hello' }],
    web_search: false,
  }),
});
// Consume response.body while awaiting response.completion.
// SSE `done` alone is not authenticated completion.
```

Title uses the same headers/rewrite option, `/v3/chat/title`, and
`{request_id, message}`. Propagate completion rejection to the UI. Actual frontend
wiring remains separate integration work.

## Usage and caching

OpenAI stream `usage` replaces Tinfoil headers/trailers. Cached counts use
`prompt_tokens_details.cached_tokens` or `prompt_cache_hit_tokens`, defaulting to
zero only when absent. Search/document counters are zero for these routes.

The existing version-2 HMAC-signed Cloudflare usage envelope/consumer contract is
retained. Only account ID, request UUID, selected model and numeric usage enter
that adapter, never prompts/completions. Admission reserves bounded queue capacity
before inference. Full/unavailable accounting rejects new work. Failed batches
are retained/retried with backpressure. Publication has timeouts, bounded bodies,
and no redirects or system proxies. Buffering remains in memory, not crash-durable;
the consumer must deduplicate request IDs and deployment/billing work must account
for abrupt termination. The consumer must recognize the new full model IDs.

A server HMAC of the authenticated user ID supplies `cache_salt`. Raw IDs and
caller-chosen cache identities are not sent to inference. This replaces Tinfoil's
cache parameter with the field supported by
[vLLM](https://docs.vllm.ai/en/latest/design/prefix_caching/) and
[SGLang](https://github.com/sgl-project/sglang/blob/main/python/sglang/srt/entrypoints/openai/protocol.py).
Actual cache isolation requires the accepted Phala serving configuration to
preserve/enforce this field; connection attestation alone does not establish that
setting. Check the deployed route before claiming cache isolation.
[Phala documents OpenAI streaming](https://docs.phala.com/phala-cloud/confidential-ai/confidential-model/streaming);
the pinned gateway source also requests `include_usage` in
`src/middleware/request_transform.rs` at revision
`a991c08553cbd0638199abfd6eace9c83ee0a891`.

## Configuration and scope

Required application settings are `DATABASE_URL` (PostgreSQL, `sslmode=verify-full`),
`CACHE_NAMESPACE_KEY` (at least 32 bytes), `INFERENCE_SYSTEM_PROMPT`,
`CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_USAGE_QUEUE_ID` (32 hex characters each),
`CLOUDFLARE_QUEUES_API_TOKEN`, and `USAGE_HMAC_SECRET` (at least 32 bytes).

Optional existing names/defaults: `DATABASE_MAX_CONNECTIONS=20`,
`INFERENCE_TEMPERATURE=0.7`, `INFERENCE_MAX_TOKENS=32000`,
`INFERENCE_MAX_CONCURRENCY=1000`. Existing Phala/authentication/Oak release settings
are also required. Database schema and queue consumer are existing external
services; this port does not provision resources or apply migrations.

Web search currently returns explicit `web_search_unavailable`, rather than
silently answering without search. Stripe changes, document processing and search
orchestration await their separately specified behavior. Their old Tinfoil paths
are not copied into this implementation.

Rust compilation validates integration. Live CVM/Phala streaming, cache enforcement,
usage delivery and browser application wiring need the configured runtime and are
not established by compilation.
