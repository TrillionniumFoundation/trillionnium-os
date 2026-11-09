use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
        value.shrink_to_fit();
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            output.push(value.0);
        }
        output.shrink_to_fit();
        Ok(UniqueJson(Value::Array(output)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = serde_json::Map::new();
        while let Some(mut key) = map.next_key::<String>()? {
            key.shrink_to_fit();
            if output.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<UniqueJson>()?;
            output.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(output)))
    }
}

pub(crate) fn decode_object(encoded: &[u8]) -> Result<Value, String> {
    allocation_bound(encoded)?;
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let UniqueJson(value) =
        UniqueJson::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    if !value.is_object() {
        return Err("provider JSONL record must be an object".to_string());
    }
    if owned_bytes(&value).map_err(|error| error.to_string())?
        > super::MAX_JSONL_PROVIDER_JSON_BYTES
    {
        return Err("provider JSON owned allocation exceeds its budget".to_string());
    }
    Ok(value)
}

pub(crate) fn allocation_bound(encoded: &[u8]) -> Result<usize, String> {
    let mut bound = encoded
        .len()
        .checked_mul(2)
        .ok_or("provider JSON budget overflow")?;
    let mut quoted = false;
    let mut escaped = false;
    let mut scalar = false;
    for byte in encoded {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        let extra = match byte {
            b'"' => {
                quoted = true;
                scalar = false;
                2 * std::mem::size_of::<Value>()
            }
            b'[' | b'{' => {
                scalar = false;
                2 * std::mem::size_of::<Value>()
            }
            b':' => {
                scalar = false;
                256
            }
            b',' | b']' | b'}' | b' ' | b'\r' | b'\n' | b'\t' => {
                scalar = false;
                0
            }
            _ if !scalar => {
                scalar = true;
                2 * std::mem::size_of::<Value>()
            }
            _ => 0,
        };
        bound = bound
            .checked_add(extra)
            .ok_or("provider JSON budget overflow")?;
        if bound > super::MAX_JSONL_PROVIDER_JSON_BYTES {
            return Err("provider JSON decode allocation exceeds its budget".into());
        }
    }
    Ok(bound)
}

pub(crate) fn owned_bytes(value: &Value) -> super::Result<usize> {
    fn weight(value: &Value, depth: usize) -> Option<usize> {
        if depth > 128 {
            return None;
        }
        match value {
            Value::String(value) => Some(value.capacity()),
            Value::Array(values) => values.iter().try_fold(
                values
                    .capacity()
                    .checked_mul(std::mem::size_of::<Value>())?,
                |sum, value| sum.checked_add(weight(value, depth + 1)?),
            ),
            Value::Object(values) => {
                values
                    .iter()
                    .try_fold(values.len().checked_mul(256)?, |sum, (key, value)| {
                        sum.checked_add(key.capacity())?
                            .checked_add(weight(value, depth + 1)?)
                    })
            }
            _ => Some(0),
        }
    }
    weight(value, 0).ok_or_else(|| super::invalid_config("provider JSON owned capacity overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dense_arrays_and_objects_fail_the_lexical_gate_before_dom_decode() {
        let array = serde_json::to_vec(&serde_json::json!({"values": vec![0u8; 100_000]})).unwrap();
        assert!(
            decode_object(&array)
                .unwrap_err()
                .contains("decode allocation")
        );
        let object = (0..12_000)
            .map(|index| (format!("k-{index}"), Value::Null))
            .collect::<serde_json::Map<_, _>>();
        let encoded = serde_json::to_vec(&Value::Object(object)).unwrap();
        assert!(
            decode_object(&encoded)
                .unwrap_err()
                .contains("decode allocation")
        );
        assert!(decode_object(br#"{"text":"[,]\"[,]"}"#).is_ok());
    }
    #[test]
    fn owned_reservation_includes_spare_string_and_array_capacity() {
        let value = Value::String(String::with_capacity(
            super::super::MAX_JSONL_PROVIDER_JSON_BYTES + 1,
        ));
        assert!(owned_bytes(&value).unwrap() > super::super::MAX_JSONL_PROVIDER_JSON_BYTES);
        let value = Value::Array(Vec::with_capacity(1024));
        assert_eq!(
            owned_bytes(&value).unwrap(),
            1024 * std::mem::size_of::<Value>()
        );
    }
}
