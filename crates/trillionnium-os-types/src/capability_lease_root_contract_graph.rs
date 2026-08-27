use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

struct Contract {
    name: &'static str,
    schema: &'static str,
    bytes: &'static [u8],
}

struct ParsedContract {
    index: usize,
    sha256: String,
    value: Value,
}

const CONTRACTS: &[Contract] = &[
    Contract {
        name: "registration",
        schema: "org.trillionnium.capabilitylease.root-registration.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-registration-v1.json"),
    },
    Contract {
        name: "publication",
        schema: "org.trillionnium.capabilitylease.root-publication.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-publication-v1.json"),
    },
    Contract {
        name: "publisher-launch",
        schema: "org.trillionnium.capabilitylease.root-publisher-launch.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-publisher-launch-v1.json"),
    },
    Contract {
        name: "authenticator",
        schema: "org.trillionnium.capabilitylease.root-authenticator.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-authenticator-v1.json"),
    },
    Contract {
        name: "proof-carrier",
        schema: "org.trillionnium.capabilitylease.root-proof-carrier.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-proof-carrier-v1.json"),
    },
    Contract {
        name: "kernel-custody",
        schema: "org.trillionnium.capabilitylease.root-kernel-custody.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-kernel-custody-v1.json"),
    },
    Contract {
        name: "socket-result-custody",
        schema: "org.trillionnium.capabilitylease.root-socket-result-custody.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-socket-result-custody-v1.json"),
    },
    Contract {
        name: "listener-correlation",
        schema: "org.trillionnium.capabilitylease.root-listener-correlation.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-listener-correlation-v1.json"),
    },
    Contract {
        name: "route-coordinator",
        schema: "org.trillionnium.capabilitylease.root-route-coordinator.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-route-coordinator-v1.json"),
    },
    Contract {
        name: "route-transport",
        schema: "org.trillionnium.capabilitylease.root-route-transport.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-route-transport-v1.json"),
    },
    Contract {
        name: "route-socket-custody",
        schema: "org.trillionnium.capabilitylease.root-route-socket-custody.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-route-socket-custody-v1.json"),
    },
    Contract {
        name: "route-session",
        schema: "org.trillionnium.capabilitylease.root-route-session.contract.v1",
        bytes: include_bytes!("../contracts/capability-lease-root-route-session-v1.json"),
    },
];

const EDGES: &[(&str, &str, &str, &str)] = &[
    (
        "publication",
        "fixed",
        "root_registration_contract_sha256",
        "registration",
    ),
    (
        "publisher-launch",
        "fixed",
        "publication_contract_sha256",
        "publication",
    ),
    (
        "authenticator",
        "dependencies",
        "root_publication_contract_sha256",
        "publication",
    ),
    (
        "authenticator",
        "dependencies",
        "root_publisher_launch_contract_sha256",
        "publisher-launch",
    ),
    (
        "proof-carrier",
        "dependencies",
        "root_authenticator_contract_sha256",
        "authenticator",
    ),
    (
        "kernel-custody",
        "dependencies",
        "root_authenticator_contract_sha256",
        "authenticator",
    ),
    (
        "kernel-custody",
        "dependencies",
        "root_proof_carrier_contract_sha256",
        "proof-carrier",
    ),
    (
        "socket-result-custody",
        "dependencies",
        "root_publication_contract_sha256",
        "publication",
    ),
    (
        "socket-result-custody",
        "dependencies",
        "root_proof_carrier_contract_sha256",
        "proof-carrier",
    ),
    (
        "socket-result-custody",
        "dependencies",
        "root_kernel_custody_contract_sha256",
        "kernel-custody",
    ),
    (
        "listener-correlation",
        "dependencies",
        "root_publication_contract_sha256",
        "publication",
    ),
    (
        "listener-correlation",
        "dependencies",
        "root_authenticator_contract_sha256",
        "authenticator",
    ),
    (
        "listener-correlation",
        "dependencies",
        "root_proof_carrier_contract_sha256",
        "proof-carrier",
    ),
    (
        "listener-correlation",
        "dependencies",
        "root_socket_result_custody_contract_sha256",
        "socket-result-custody",
    ),
    (
        "route-coordinator",
        "dependencies",
        "root_kernel_custody_contract_sha256",
        "kernel-custody",
    ),
    (
        "route-coordinator",
        "dependencies",
        "root_socket_result_custody_contract_sha256",
        "socket-result-custody",
    ),
    (
        "route-coordinator",
        "dependencies",
        "root_listener_correlation_contract_sha256",
        "listener-correlation",
    ),
    (
        "route-transport",
        "dependencies",
        "root_route_coordinator_contract_sha256",
        "route-coordinator",
    ),
    (
        "route-socket-custody",
        "dependencies",
        "root_route_transport_contract_sha256",
        "route-transport",
    ),
    (
        "route-session",
        "dependencies",
        "root_route_coordinator_contract_sha256",
        "route-coordinator",
    ),
    (
        "route-session",
        "dependencies",
        "root_route_transport_contract_sha256",
        "route-transport",
    ),
    (
        "route-session",
        "dependencies",
        "root_route_socket_custody_contract_sha256",
        "route-socket-custody",
    ),
];

#[test]
fn all_twelve_contracts_form_one_strict_exact_dependency_dag() {
    assert_eq!(CONTRACTS.len(), 12);
    assert_eq!(EDGES.len(), 22);

    let mut parsed = BTreeMap::new();
    for (index, contract) in CONTRACTS.iter().enumerate() {
        let value = parse_strict_json(contract.bytes).unwrap_or_else(|error| {
            panic!("{} contract is not strict JSON: {error}", contract.name)
        });
        assert_eq!(
            value.get("contract_schema").and_then(Value::as_str),
            Some(contract.schema),
            "{} contract schema drifted",
            contract.name
        );
        assert!(
            parsed
                .insert(
                    contract.name,
                    ParsedContract {
                        index,
                        sha256: crate::sha256_bytes(contract.bytes),
                        value,
                    },
                )
                .is_none(),
            "duplicate contract name: {}",
            contract.name
        );
    }

    let expected_edges = EDGES
        .iter()
        .map(|(source, section, field, _)| {
            (
                (*source).to_string(),
                (*section).to_string(),
                (*field).to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut declared_edges = BTreeSet::new();

    for (source_name, source) in &parsed {
        collect_declared_edges(
            source_name,
            &source.value,
            &mut Vec::new(),
            &mut declared_edges,
        );
    }
    assert_eq!(
        declared_edges, expected_edges,
        "contract dependency fields escaped the closed graph"
    );

    for (source_name, section, field, target_name) in EDGES {
        let source = parsed
            .get(source_name)
            .unwrap_or_else(|| panic!("missing source contract: {source_name}"));
        let target = parsed
            .get(target_name)
            .unwrap_or_else(|| panic!("missing target contract: {target_name}"));
        assert!(
            target.index < source.index,
            "{source_name}/{field} violates the reviewed topological order"
        );
        assert_eq!(
            source
                .value
                .get(section)
                .and_then(|value| value.get(field))
                .and_then(Value::as_str),
            Some(target.sha256.as_str()),
            "{source_name}/{section}/{field} does not bind the exact {target_name} bytes"
        );
    }
}

#[test]
fn strict_json_rejects_duplicate_nested_trailing_and_float_material() {
    assert!(parse_strict_json(br#"{"field":1,"field":2}"#).is_err());
    assert!(parse_strict_json(br#"{"nested":{"field":1,"field":2}}"#).is_err());
    assert!(parse_strict_json(br#"{"field":1} trailing"#).is_err());
    assert!(parse_strict_json(br#"{"field":1.0}"#).is_err());
}

fn collect_declared_edges(
    source: &str,
    value: &Value,
    path: &mut Vec<String>,
    output: &mut BTreeSet<(String, String, String)>,
) {
    if let Some(array) = value.as_array() {
        for (index, nested) in array.iter().enumerate() {
            path.push(format!("[{index}]"));
            collect_declared_edges(source, nested, path, output);
            path.pop();
        }
        return;
    }
    let Some(object) = value.as_object() else {
        return;
    };
    for (field, nested) in object {
        if field.ends_with("_contract_sha256") {
            assert_eq!(
                path.len(),
                1,
                "{source}/{field} escaped the reviewed dependency section depth"
            );
            output.insert((source.to_string(), path[0].clone(), field.clone()));
        }
        path.push(field.clone());
        collect_declared_edges(source, nested, path, output);
        path.pop();
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate keys or floating-point values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(
            "floating-point values are forbidden in capability-root contracts",
        ))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON field: {key}")));
            }
            let value = entries.next_value_seed(StrictValue)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
