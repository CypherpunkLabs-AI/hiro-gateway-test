//! Bounded, duplicate-rejecting JSON and canonical hexadecimal parsing.

use evidence_sha2::{Digest, Sha256};
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::{Error, Result};

pub(crate) const MAX_DOCUMENT: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 131_072;
const MAX_DEPTH: usize = 32;

pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Limit);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0;
    let mut expanded = 0;
    let value = Seed {
        depth: 0,
        nodes: &mut nodes,
        expanded: &mut expanded,
    }
    .deserialize(&mut decoder)
    .map_err(|_| Error::Encoding)?;
    decoder.end().map_err(|_| Error::Encoding)?;
    serde_json::from_value(value).map_err(|_| Error::Encoding)
}

pub(crate) fn parse_yaml<T: DeserializeOwned>(bytes: &str, limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Limit);
    }
    let mut nodes = 0;
    let mut expanded = 0;
    let value = Seed {
        depth: 0,
        nodes: &mut nodes,
        expanded: &mut expanded,
    }
    .deserialize(serde_yaml_ng::Deserializer::from_str(bytes))
    .map_err(|_| Error::Encoding)?;
    serde_json::from_value(value).map_err(|_| Error::Encoding)
}

struct Seed<'a> {
    depth: usize,
    nodes: &'a mut usize,
    expanded: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> core::result::Result<Value, D::Error> {
        *self.nodes += 1;
        if self.depth > MAX_DEPTH || *self.nodes > MAX_NODES {
            return Err(serde::de::Error::custom("JSON resource limit"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bounded JSON without duplicate object fields")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> core::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> core::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> core::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> core::result::Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: serde::de::Error>(mut self, value: &str) -> core::result::Result<Value, E> {
        self.reserve::<E>(value.len())?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(
        mut self,
        value: String,
    ) -> core::result::Result<Value, E> {
        self.reserve::<E>(value.len())?;
        Ok(Value::String(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> core::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> core::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> core::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(Seed {
            depth: self.depth + 1,
            nodes: self.nodes,
            expanded: self.expanded,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(
        mut self,
        mut access: A,
    ) -> core::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            self.reserve::<A::Error>(key.len())?;
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate object field"));
            }
            let value = access.next_value_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
                expanded: self.expanded,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Encoding);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Encoding)?;
    Ok(bytes)
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn text(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::Encoding);
    }
    Ok(())
}

impl Seed<'_> {
    fn reserve<E: serde::de::Error>(&mut self, length: usize) -> core::result::Result<(), E> {
        let size = self
            .expanded
            .checked_add(length)
            .ok_or_else(|| E::custom("expanded byte limit"))?;
        if size > MAX_DOCUMENT {
            return Err(E::custom("expanded byte limit"));
        }
        *self.expanded = size;
        Ok(())
    }
}
