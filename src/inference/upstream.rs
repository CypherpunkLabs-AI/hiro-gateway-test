//! Bounded inference forwarding authorized by verified attestation and TLS pins.
use crate::attestation::VerifiedUpstream;
use anyhow::{Context, Result, ensure};
use futures_util::{Stream, StreamExt};
use std::{collections::HashMap, pin::Pin, time::Duration};

#[derive(Default)]
pub struct UpstreamRequest {
    pub body: Vec<u8>,
    pub path: Option<String>,
    pub headers: HashMap<String, String>,
}
pub struct PreparedRequest {
    pub(crate) request: UpstreamRequest,
    pub(crate) upstream_name: String,
    pub(crate) url_origin: Option<String>,
    pub(crate) model_id: String,
}
pub struct StreamResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Pin<Box<dyn Stream<Item = Result<axum::body::Bytes>> + Send>>,
}
pub struct Response {
    pub status_code: u16,
    pub body: Vec<u8>,
}

pub struct InferenceBackend {
    origin: String,
    credential: zeroize::Zeroizing<String>,
    connect_timeout: Duration,
    read_timeout: Duration,
}

pub(crate) fn validate_origin(origin: &str) -> Result<()> {
    let url = reqwest::Url::parse(origin)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && !origin.ends_with('/'),
        "invalid inference base URL"
    );
    Ok(())
}

impl InferenceBackend {
    pub fn new(origin: &str, credential: String, connect: u64, read: u64) -> Result<Self> {
        validate_origin(origin)?;
        ensure!(!credential.is_empty(), "inference credential required");
        Ok(Self {
            origin: origin.into(),
            credential: zeroize::Zeroizing::new(credential),
            connect_timeout: Duration::from_secs(connect),
            read_timeout: Duration::from_secs(read),
        })
    }
    pub fn prepare(&self, request: UpstreamRequest) -> Result<PreparedRequest> {
        let path = request.path.as_deref().context("inference path required")?;
        ensure!(
            crate::transport::inference_route(path),
            "unsupported inference route"
        );
        ensure!(
            request.body.len() <= 64 * 1024 * 1024,
            "request exceeds limit"
        );
        ensure!(
            request.headers.keys().all(|name| matches!(
                name.as_str(),
                "content-type" | "accept" | "anthropic-version"
            )),
            "unsupported upstream header"
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body)?;
        let model = body
            .get("model")
            .and_then(serde_json::Value::as_str)
            .context("model required")?;
        ensure!(!model.is_empty() && model.len() <= 512, "invalid model");
        let model_id = model.to_owned();
        Ok(PreparedRequest {
            request,
            upstream_name: "phala-aci".into(),
            url_origin: Some(self.origin.clone()),
            model_id,
        })
    }
    async fn send(
        &self,
        prepared: PreparedRequest,
        verified: &VerifiedUpstream,
    ) -> Result<reqwest::Response> {
        let path = prepared
            .request
            .path
            .as_deref()
            .context("inference path required")?;
        let pins = verified.authorize(
            &self.origin,
            path,
            &prepared.model_id,
            &prepared.request.body,
        )?;
        let client = crate::inference::tls::pinned_client(
            &self.origin,
            &pins,
            self.connect_timeout,
            self.read_timeout,
        )?;
        let mut request = client
            .post(format!("{}{path}", self.origin))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        for (name, value) in prepared.request.headers {
            request = request.header(name, value);
        }
        // The body and bearer token are sent only through the pinned TLS client.
        request = request
            .bearer_auth(self.credential.as_str())
            .body(prepared.request.body);
        ensure!(
            verified.is_current(),
            "upstream authority expired before dispatch"
        );
        request
            .send()
            .await
            .context("attested inference connection failed")
    }
    pub async fn forward_stream_verified_prepared(
        &self,
        prepared: PreparedRequest,
        verified: &VerifiedUpstream,
    ) -> Result<StreamResponse> {
        let response = self.send(prepared, verified).await?;
        let status_code = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|_| anyhow::anyhow!("upstream response interrupted")));
        Ok(StreamResponse {
            status_code,
            headers,
            body: Box::pin(body),
        })
    }
    pub async fn forward_verified_prepared(
        &self,
        prepared: PreparedRequest,
        verified: &VerifiedUpstream,
    ) -> Result<Response> {
        let response = self.send(prepared, verified).await?;
        let status_code = response.status().as_u16();
        Ok(Response {
            status_code,
            body: bounded_body(response, 1024 * 1024).await?,
        })
    }
}

pub(crate) async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "upstream body exceeds limit"
    );
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("upstream body interrupted")?;
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "upstream body exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
