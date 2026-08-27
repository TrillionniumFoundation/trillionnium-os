use std::collections::HashSet;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::{Result, ToolRuntimeError};

/// Decode an authenticated gateway frame without duplicate-key, trailing-data,
/// or floating-point ambiguity. This parser belongs to the live Context/Memory
/// transport and therefore remains independent of the retired effect receipt
/// verifier.
pub(crate) fn parse(encoded: &str, boundary: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(encoded);
    let StrictJson(value) = StrictJson::deserialize(&mut deserializer).map_err(|error| {
        ToolRuntimeError::AndroidGatewayProtocol(format!(
            "{boundary} is not strict canonical JSON: {error}"
        ))
    })?;
    deserializer.end().map_err(|error| {
        ToolRuntimeError::AndroidGatewayProtocol(format!("{boundary} has trailing data: {error}"))
    })?;
    Ok(value)
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(StrictJsonVisitor)
            .map(StrictJson)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict JSON without duplicate keys or floating-point numbers")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point numbers are denied"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            output.push(value.0);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut fields = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !fields.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<StrictJson>()?;
            output.insert(key, value.0);
        }
        Ok(Value::Object(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_closed_integer_json() {
        assert_eq!(
            parse(r#"{"a":[1,true,null]}"#, "fixture").unwrap()["a"][0],
            1
        );
    }

    #[test]
    fn rejects_duplicate_keys_recursively() {
        assert!(parse(r#"{"a":{"b":1,"b":2}}"#, "fixture").is_err());
    }

    #[test]
    fn rejects_floats_and_trailing_data() {
        assert!(parse(r#"{"a":1.5}"#, "fixture").is_err());
        assert!(parse(r#"{"a":1} {}"#, "fixture").is_err());
    }
}
