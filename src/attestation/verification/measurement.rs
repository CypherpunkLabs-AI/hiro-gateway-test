//! Replay measured runtime events and verify exact composition preimages.

use std::collections::BTreeMap;

use aci_verify::dstack::{
    DstackEventLog, dstack_app_id, verify_dstack_compose_measurement, verify_dstack_event_log,
};
use evidence_sha2::{Digest, Sha384};
use serde::Deserialize;
use serde_json::Value;

use super::{Error, Result, encoding};

const RUNTIME: u32 = 0x0800_0001;

pub(crate) fn verify(
    evidence: &Value,
    rtmr3: &[u8; 48],
    app_id: &str,
    compose_hash: &str,
) -> Result<()> {
    let log = evidence
        .get("event_log")
        .and_then(Value::as_str)
        .ok_or(Error::Measurement)?;
    let entries: Vec<DstackEventLog> = encoding::parse(log.as_bytes(), 1024 * 1024)?;
    if entries.is_empty() || entries.len() > 2048 {
        return Err(Error::Limit);
    }
    let mut ready = false;
    for entry in &entries {
        if entry.imr > 3 || entry.event.len() > 128 || entry.event_payload.len() > 16 * 1024 {
            return Err(Error::Measurement);
        }
        let reported = encoding::hex_array::<48>(&entry.digest)?;
        if entry.event_type == RUNTIME {
            let payload = hex::decode(&entry.event_payload).map_err(|_| Error::Measurement)?;
            let mut digest = Sha384::new();
            digest.update(RUNTIME.to_le_bytes());
            digest.update(b":");
            digest.update(entry.event.as_bytes());
            digest.update(b":");
            digest.update(payload);
            let computed: [u8; 48] = digest.finalize().into();
            if reported != computed {
                return Err(Error::Measurement);
            }
            if entry.imr == 3 {
                if entry.event == "system-ready" {
                    if ready {
                        return Err(Error::Measurement);
                    }
                    ready = true;
                } else if ready && ["compose-hash", "app-id"].contains(&entry.event.as_str()) {
                    return Err(Error::Measurement);
                }
            }
        }
    }
    if !ready {
        return Err(Error::Measurement);
    }
    let verified =
        verify_dstack_event_log(evidence, Some(rtmr3)).map_err(|_| Error::Measurement)?;
    if hex::encode(dstack_app_id(&verified).map_err(|_| Error::Measurement)?) != app_id
        || verify_dstack_compose_measurement(evidence, &verified).map_err(|_| Error::Measurement)?
            != compose_hash
    {
        return Err(Error::Measurement);
    }
    Ok(())
}

#[derive(Deserialize)]
struct Compose {
    services: BTreeMap<String, Service>,
    #[serde(default)]
    include: Option<Value>,
}

#[derive(Deserialize)]
struct Service {
    image: String,
    #[serde(default)]
    build: Option<Value>,
    #[serde(default)]
    extends: Option<Value>,
}

pub(crate) fn containers(evidence: &Value, expected: &BTreeMap<String, String>) -> Result<()> {
    let app = evidence
        .get("app_compose")
        .and_then(Value::as_str)
        .ok_or(Error::Measurement)?;
    let app: Value = encoding::parse(app.as_bytes(), 256 * 1024)?;
    let yaml = app
        .get("docker_compose_file")
        .and_then(Value::as_str)
        .ok_or(Error::Measurement)?;
    if yaml.len() > 128 * 1024 {
        return Err(Error::Limit);
    }
    // The shared visitor counts expanded alias nodes, caps depth, rejects tags,
    // and rejects duplicate fields before converting to typed records.
    let compose: Compose = encoding::parse_yaml(yaml, 128 * 1024)?;
    if compose.include.is_some() || compose.services.len() != expected.len() {
        return Err(Error::Measurement);
    }
    for (name, service) in compose.services {
        if service.build.is_some()
            || service.extends.is_some()
            || service.image.contains('$')
            || expected.get(&name) != Some(&service.image)
        {
            return Err(Error::Measurement);
        }
    }
    Ok(())
}
