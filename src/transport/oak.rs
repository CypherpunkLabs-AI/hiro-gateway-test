//! WSS carrier for the shared Oak protocol. Private dispatch never crosses a socket.
use crate::attestation::gate::Gate;
use crate::services::inference::Service;
use crate::transport::{
    Flow, ServerChannel, Side,
    wire::{self, record::Kind},
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc},
    time::{Instant, timeout, timeout_at},
};
use tower::ServiceExt;

#[derive(Clone)]
pub struct Gateway {
    service: Arc<Service>,
    binding: Arc<SigningKey>,
    inner: Router,
    evidence: Gate,
    slots: Arc<Semaphore>,
    quotes: Arc<Semaphore>,
}
impl Gateway {
    /// Configure in-CVM transport with public evidence artifacts.
    /// # Errors
    /// Rejects unavailable, malformed or excessive evidence metadata.
    pub fn new(
        service: Arc<Service>,
        binding: Arc<SigningKey>,
        inner: Router,
        evidence: Gate,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            service,
            binding,
            inner,
            evidence,
            slots: Arc::new(Semaphore::new(8)),
            quotes: Arc::new(Semaphore::new(2)),
        })
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/session", get(upgrade))
            .with_state(self)
    }
}
async fn upgrade(
    State(state): State<Gateway>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !state.evidence.ready().await {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if !headers
        .get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            h.split(',')
                .any(|p| p.trim() == crate::transport::SUBPROTOCOL)
        })
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(permit) = state.slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    ws.protocols([crate::transport::SUBPROTOCOL])
        .max_message_size(crate::transport::MAX_FRAME)
        .max_frame_size(crate::transport::MAX_FRAME)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            // Errors deliberately omit peer payloads, tokens, evidence and key data.
            if serve(socket, state).await.is_err() {
                tracing::debug!("Oak connection closed before authenticated completion");
            }
        })
        .into_response()
}
async fn binary(socket: &mut WebSocket) -> anyhow::Result<Vec<u8>> {
    match socket.recv().await.context("carrier closed")?? {
        Message::Binary(bytes) => Ok(bytes.to_vec()),
        _ => anyhow::bail!("binary carrier record required"),
    }
}
async fn send(
    socket: &mut WebSocket,
    channel: &mut ServerChannel,
    flow: &mut Flow,
    id: &[u8],
    kind: Kind,
) -> anyhow::Result<()> {
    let record = wire::Record {
        version: 1,
        id: id.to_vec(),
        kind: Some(kind),
    };
    flow.accept(Side::Server, &record)?;
    timeout(
        Duration::from_secs(30),
        socket.send(Message::Binary(channel.send(&record)?.into())),
    )
    .await??;
    Ok(())
}
#[allow(
    clippy::single_match_else,
    reason = "explicit timeout outcome branches"
)]
async fn serve(mut socket: WebSocket, state: Gateway) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(900);
    let (mut channel, ()) = timeout(Duration::from_secs(60), async {
        let nonce = crate::transport::parse_initialize(&binary(&mut socket).await?)?;
        let _quote = state.quotes.clone().try_acquire_owned()?;
        let report = state.service.attestation_report(Some(nonce)).await?;
        let evidence = state
            .evidence
            .metadata()
            .await?
            .with_report(serde_json::to_value(report)?)?;
        let (mut channel, flight) = ServerChannel::new(evidence, state.binding.clone())?;
        socket.send(Message::Binary(flight.into())).await?;
        for _ in 0..2 {
            if channel.is_open() {
                break;
            }
            let flight = binary(&mut socket).await?;
            if let Some(outgoing) = channel.handshake(&flight)? {
                socket.send(Message::Binary(outgoing.into())).await?;
            }
        }
        ensure!(channel.is_open(), "incomplete Oak handshake");
        ensure!(
            state.evidence.ready().await,
            "evidence expired during handshake"
        );
        Ok::<_, anyhow::Error>((channel, ()))
    })
    .await??;
    let mut flow = Flow::default();
    for _ in 0..crate::transport::MAX_REQUESTS {
        let bytes = timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(60)),
            binary(&mut socket),
        )
        .await??;
        let record = channel.receive(&bytes)?;
        flow.accept(Side::Client, &record)?;
        let id = record.id;
        let Some(Kind::RequestStart(start)) = record.kind else {
            anyhow::bail!("request start required")
        };
        let request_deadline = deadline.min(Instant::now() + Duration::from_secs(660));
        let result = timeout_at(
            request_deadline,
            operation(&mut socket, &mut channel, &mut flow, &id, start, &state),
        )
        .await;
        match result {
            Ok(result) => {
                result?;
                while flow.active() {
                    let record = timeout_at(
                        deadline.min(Instant::now() + Duration::from_secs(30)),
                        incoming(&mut socket, &mut channel, &mut flow),
                    )
                    .await??;
                    ensure!(
                        matches!(
                            record.kind,
                            Some(Kind::TerminalAck(_) | Kind::ResponseCredit(_) | Kind::Cancel(_))
                        ),
                        "terminal acknowledgement required"
                    );
                }
            }
            Err(_) => {
                send(
                    &mut socket,
                    &mut channel,
                    &mut flow,
                    &id,
                    Kind::Failure(wire::Failure {
                        code: "deadline".into(),
                    }),
                )
                .await?;
                break;
            }
        }
    }
    Ok(())
}
async fn incoming(
    socket: &mut WebSocket,
    channel: &mut ServerChannel,
    flow: &mut Flow,
) -> anyhow::Result<wire::Record> {
    let bytes = binary(socket).await?;
    let record = channel.receive(&bytes)?;
    flow.accept(Side::Client, &record)?;
    Ok(record)
}
#[allow(
    clippy::too_many_lines,
    reason = "linear per-operation upload/response state machine"
)]
async fn operation(
    socket: &mut WebSocket,
    channel: &mut ServerChannel,
    flow: &mut Flow,
    id: &[u8],
    start: wire::Start,
    state: &Gateway,
) -> anyhow::Result<()> {
    let mut body = Vec::new();
    loop {
        let record = incoming(socket, channel, flow).await?;
        match record.kind.context("record missing")? {
            Kind::RequestData(data) => {
                let count = u32::try_from(data.body.len())?;
                body.extend(data.body);
                send(
                    socket,
                    channel,
                    flow,
                    id,
                    Kind::UploadCredit(wire::Credit { bytes: count }),
                )
                .await?;
            }
            Kind::RequestEnd(_) => break,
            Kind::Cancel(_) => {
                send(socket, channel, flow, id, Kind::Cancelled(wire::Empty {})).await?;
                return Ok(());
            }
            _ => anyhow::bail!("unexpected upload record"),
        }
    }
    let mut request = Request::builder()
        .method(start.method.as_str())
        .uri(&start.path);
    for header in &start.headers {
        request = request.header(&header.name, &header.value);
    }
    let request = request.body(Body::from(body))?;
    let (tx, mut rx) = mpsc::channel::<Output>(2);
    let inner = state.inner.clone();
    let task = tokio::spawn(async move { dispatch(inner, request, tx).await });
    // Dropping a JoinHandle detaches; AbortOnDrop explicitly cancels upstream I/O.
    let _task = AbortOnDrop(task);
    let mut receipt_id = None;
    let mut pending: Option<Bytes> = None;
    loop {
        if pending.as_ref().is_some_and(|bytes| !bytes.is_empty()) && flow.credit(Side::Server) > 0
        {
            let bytes = pending.as_mut().context("missing chunk")?;
            let count = bytes
                .len()
                .min(crate::transport::MAX_CHUNK)
                .min(flow.credit(Side::Server) as usize);
            let body = bytes.split_to(count).to_vec();
            let index = flow.index(Side::Server)?;
            send(
                socket,
                channel,
                flow,
                id,
                Kind::ResponseData(wire::Data { index, body }),
            )
            .await?;
            continue;
        }
        tokio::select! {
            record = incoming(socket, channel, flow) => {
                match record?.kind.context("record missing")? {
                    Kind::Cancel(_) => { send(socket, channel, flow, id, Kind::Cancelled(wire::Empty {})).await?; return Ok(()); },
                    Kind::ResponseCredit(_) => {},
                    _ => anyhow::bail!("unexpected response-phase client record"),
                }
            },
            output = rx.recv(), if pending.as_ref().is_none_or(Bytes::is_empty) => {
                match output.context("upstream response incomplete")? {
                    Output::Start(status, headers, receipt) => { receipt_id = receipt; send(socket, channel, flow, id, Kind::ResponseStart(wire::Response { status, headers })).await?; },
                    Output::Data(bytes) => pending = Some(bytes),
                    Output::Failed => { send(socket, channel, flow, id, Kind::Failure(wire::Failure { code: "upstream_failed".into() })).await?; return Ok(()); },
                    Output::Rejected => { send(socket, channel, flow, id, Kind::Failure(wire::Failure { code: "request_rejected".into() })).await?; return Ok(()); },
                    Output::End => break,
                }
            }
        }
    }
    let mut completion = wire::Completion {
        body: Some(flow.end(Side::Server)?),
        receipt_id: String::new(),
        receipt: Vec::new(),
        session: Vec::new(),
    };
    if crate::transport::inference_route(&start.path) {
        let proof = receipt_id.and_then(|id| state.service.take_completion(&id));
        let Some((receipt, session)) = proof else {
            send(
                socket,
                channel,
                flow,
                id,
                Kind::Failure(wire::Failure {
                    code: "receipt_unavailable".into(),
                }),
            )
            .await?;
            return Ok(());
        };
        completion.receipt_id = receipt.receipt_id;
        completion.receipt = receipt.document;
        completion.session = session.bytes().to_vec();
    }
    send(socket, channel, flow, id, Kind::ResponseEnd(completion)).await
}
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
enum Output {
    Start(u32, Vec<wire::Header>, Option<String>),
    Data(Bytes),
    End,
    Failed,
    Rejected,
}
async fn dispatch(inner: Router, request: Request<Body>, tx: mpsc::Sender<Output>) {
    let Ok(response) = inner.oneshot(request).await;
    let rejected = response
        .extensions()
        .get::<crate::auth::AuthError>()
        .is_some()
        || response
            .extensions()
            .get::<crate::inference::error::ApiError>()
            .is_some();
    let receipt = response
        .headers()
        .get("x-receipt-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let headers = response
        .headers()
        .iter()
        .filter(|(key, _)| {
            matches!(
                key.as_str(),
                "content-type" | "x-request-id" | "cache-control" | "retry-after"
            )
        })
        .filter_map(|(key, value)| {
            value.to_str().ok().map(|value| wire::Header {
                name: key.to_string(),
                value: value.into(),
            })
        })
        .collect();
    if tx
        .send(Output::Start(
            u32::from(response.status().as_u16()),
            headers,
            receipt,
        ))
        .await
        .is_err()
    {
        return;
    }
    let mut stream = response.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(mut bytes) = chunk else {
            let _ = tx.send(Output::Failed).await;
            return;
        };
        while !bytes.is_empty() {
            let count = bytes.len().min(crate::transport::MAX_CHUNK);
            // copy_from_slice prevents a small queued slice retaining an entire huge allocation.
            let part = Bytes::copy_from_slice(&bytes.split_to(count));
            if tx.send(Output::Data(part)).await.is_err() {
                return;
            }
        }
    }
    let _ = tx
        .send(if rejected {
            Output::Rejected
        } else {
            Output::End
        })
        .await;
}
