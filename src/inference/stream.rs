//! `OpenAI` SSE decoding over the already attested, pinned Phala connection.
use super::upstream::StreamResponse;
use anyhow::{Context, ensure};
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use serde_json::Value;
use std::pin::Pin;

#[derive(Debug, Clone, Copy)]
pub(crate) struct UsageMetrics {
    pub prompt_tokens: i64,
    pub cached_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub web_search_calls: i64,
    pub document_parse_calls: i64,
}

impl UsageMetrics {
    fn parse(value: &Value) -> anyhow::Result<Self> {
        let count = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_i64)
                .filter(|v| *v >= 0)
                .with_context(|| format!("invalid usage {name}"))
        };
        let prompt_tokens = count("prompt_tokens")?;
        let completion_tokens = count("completion_tokens")?;
        let total_tokens = count("total_tokens")?;
        let cached = value
            .pointer("/prompt_tokens_details/cached_tokens")
            .or_else(|| value.get("prompt_cache_hit_tokens"));
        let cached_tokens = match cached {
            Some(v) => v.as_i64().context("invalid cached usage")?,
            None => 0,
        };
        ensure!(
            (0..=prompt_tokens).contains(&cached_tokens)
                && prompt_tokens.checked_add(completion_tokens) == Some(total_tokens),
            "inconsistent usage"
        );
        Ok(Self {
            prompt_tokens,
            cached_tokens,
            completion_tokens,
            total_tokens,
            web_search_calls: 0,
            document_parse_calls: 0,
        })
    }
}

pub(crate) enum Event {
    Chunk(Value),
    Usage(UsageMetrics),
}
pub(crate) type EventStream = Pin<Box<dyn Stream<Item = anyhow::Result<Event>> + Send>>;

pub(crate) fn decode(response: StreamResponse) -> anyhow::Result<EventStream> {
    ensure!(
        (200..300).contains(&response.status_code),
        "inference rejected"
    );
    ensure!(
        response
            .headers
            .get("content-type")
            .and_then(|s| s.split(';').next())
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("text/event-stream")),
        "inference did not return SSE"
    );
    let mut body = response.body;
    let bounded = async_stream::try_stream! {
        let mut total = 0usize;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            total = total.checked_add(chunk.len()).context("response limit")?;
            require(total <= 64 * 1024 * 1024, "response limit")?;
            yield chunk;
        }
    };
    let bounded: Pin<Box<dyn Stream<Item = anyhow::Result<axum::body::Bytes>> + Send>> =
        Box::pin(bounded);
    Ok(Box::pin(async_stream::try_stream! {
        let mut events = bounded.eventsource();
        let mut finished = false;
        let mut usage = None;
        let mut done = false;
        while let Some(event) = events.next().await {
            let event = event.map_err(|_| anyhow::anyhow!("invalid inference stream"))?;
            require(event.event.is_empty() || event.event == "message", "unexpected inference event")?;
            if event.data.trim() == "[DONE]" {
                require(finished, "inference ended without finish reason")?;
                yield Event::Usage(usage.take().context("inference ended without usage")?);
                done = true;
                break;
            }
            let value: Value = serde_json::from_str(&event.data).context("invalid inference event")?;
            require(value.get("error").is_none(), "inference stream failed")?;
            if let Some(metrics) = value.get("usage").filter(|v| !v.is_null()) {
                usage = Some(UsageMetrics::parse(metrics)?);
            }
            let choices = value.get("choices").and_then(Value::as_array).context("missing inference choices")?;
            require(choices.len() <= 1, "unexpected inference choices")?;
            if let Some(choice) = choices.first() {
                require(!finished && choice.get("index").and_then(Value::as_u64) == Some(0) && choice.get("delta").is_some_and(Value::is_object), "invalid inference choice")?;
                if let Some(reason) = choice.get("finish_reason").filter(|v| !v.is_null()) {
                    require(matches!(reason.as_str(), Some("stop" | "length" | "content_filter")), "unsupported inference finish reason")?;
                    finished = true;
                }
                yield Event::Chunk(value);
            }
        }
        require(done, "inference stream truncated")?;
    }))
}

fn require(condition: bool, message: &str) -> anyhow::Result<()> {
    ensure!(condition, "{message}");
    Ok(())
}
