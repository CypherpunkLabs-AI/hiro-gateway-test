use super::error::ApiError;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChatRequest {
    pub(crate) request_id: Uuid,
    pub(crate) messages: Vec<ClientChatMessage>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) web_search: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientChatMessage {
    pub(crate) role: ClientChatRole,
    pub(crate) content: ClientChatContent,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum ClientChatContent {
    Text(String),
    Parts(Vec<ClientChatContentPart>),
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClientChatContentPart {
    Text { text: String },
    ImageUrl { image_url: ClientImageUrl },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientImageUrl {
    url: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ClientChatRole {
    User,
    Assistant,
}

pub(crate) fn validate_chat(input: &ChatRequest) -> Result<(), ApiError> {
    if input.messages.is_empty() || input.messages.len() > 128 {
        return Err(ApiError::BadRequest(
            "messages must contain 1..128 entries".into(),
        ));
    }
    let mut text_bytes = 0_usize;
    let mut image_bytes = 0_usize;
    let mut image_count = 0_usize;
    for message in &input.messages {
        match &message.content {
            ClientChatContent::Text(text) => {
                if text.is_empty() {
                    return Err(invalid_content());
                }
                text_bytes = text_bytes.saturating_add(text.len());
            }
            ClientChatContent::Parts(parts) => {
                if parts.is_empty() || parts.len() > 64 {
                    return Err(invalid_content());
                }
                if matches!(message.role, ClientChatRole::Assistant)
                    && parts
                        .iter()
                        .any(|part| matches!(part, ClientChatContentPart::ImageUrl { .. }))
                {
                    return Err(ApiError::BadRequest(
                        "assistant messages cannot contain images".into(),
                    ));
                }
                for part in parts {
                    match part {
                        ClientChatContentPart::Text { text } => {
                            if text.is_empty() {
                                return Err(invalid_content());
                            }
                            text_bytes = text_bytes.saturating_add(text.len());
                        }
                        ClientChatContentPart::ImageUrl { image_url } => {
                            image_count += 1;
                            image_bytes = image_bytes
                                .saturating_add(validate_image_data_url(&image_url.url)?);
                        }
                    }
                }
            }
        }
    }
    if text_bytes > 20 * 1024 * 1024 || image_count > 20 || image_bytes > 20 * 1024 * 1024 {
        return Err(ApiError::BadRequest(
            "message content exceeds the text or image limit".into(),
        ));
    }
    Ok(())
}

fn invalid_content() -> ApiError {
    ApiError::BadRequest("message content is empty or invalid".into())
}

fn validate_image_data_url(url: &str) -> Result<usize, ApiError> {
    const PREFIXES: [&str; 4] = [
        "data:image/jpeg;base64,",
        "data:image/png;base64,",
        "data:image/webp;base64,",
        "data:image/gif;base64,",
    ];
    let payload = PREFIXES
        .iter()
        .find_map(|prefix| url.strip_prefix(prefix))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "image_url must be a base64 JPEG, PNG, WebP, or GIF data URL".into(),
            )
        })?;
    if payload.is_empty() || payload.len() > 28 * 1024 * 1024 {
        return Err(ApiError::BadRequest(
            "image_url contains invalid base64 data".into(),
        ));
    }
    STANDARD
        .decode(payload)
        .map(|bytes| bytes.len())
        .map_err(|_| ApiError::BadRequest("image_url contains invalid base64 data".into()))
}
