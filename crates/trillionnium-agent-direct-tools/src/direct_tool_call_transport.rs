//! Adapter client for the dedicated Direct operation tool-call session.
//!
//! This is not the capability-lease root-publication channel. A product call
//! can reach the backend only after this client has recovered a daemon-
//! preissued logical delivery, durably written the matching operation as
//! PREPARED, and received the allocator's durable commit receipt. The fixed
//! connected Unix socket supplies the daemon identity; no identity field in a
//! received frame is treated as an authority constructor.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
use std::path::Path;
#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
use trillionnium_os_types::direct_operation::{
    ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, DirectOperationAdapterTerminalDispositionV1,
    DirectOperationAdapterTerminalStateV1, DirectOperationToolCallAllocationRequestV3,
    DirectOperationToolCallCommitReceiptV3, DirectOperationToolCallDeliveryV3,
    DirectOperationToolCallEnvelopeV3,
};
use trillionnium_os_types::direct_operation_tool_call_transport as contract;
#[cfg(feature = "production-durable-hotpath")]
use trillionnium_os_types::direct_operation_tool_call_transport::DirectOperationToolCallSessionHelloV3;
#[cfg(feature = "device-launch-package-conformance")]
use trillionnium_os_types::direct_operation_tool_call_transport::P0UserdebugAdapterTerminalCommitV1;
#[cfg(feature = "device-launch-package-conformance")]
use trillionnium_os_types::direct_operation_tool_call_transport::P0UserdebugDirectOperationToolCallSessionHelloV1;

use crate::{DirectToolError, Result};

#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Complete the daemon allocation/PREPARED receipt transaction before one
/// product backend effect. Every input identity comes from the already
/// authenticated launch context or the durable journal; the model request
/// contributes only canonical bytes.
#[cfg(feature = "production-durable-hotpath")]
pub(crate) fn prepare_product_effect(
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
    canonical_request: &[u8],
) -> Result<crate::operation_journal::PreparedOperation> {
    context
        .require_product_effect_custody()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let custody = context
        .kernel_launch_custody_for_direct_transport()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;

    let hello = DirectOperationToolCallSessionHelloV3::derive(
        context.binding(),
        context.binding_sha256(),
        context.adapter(),
        custody,
    )
    .map_err(protocol_error)?;
    prepare_effect_with_hello(context, journal, canonical_request, &hello)
}

/// Complete the same allocation/PREPARED transaction for the distinct P0
/// userdebug conformance lane without claiming production kernel custody.
/// Live peer measurement and exact executable admission remain daemon-owned.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn prepare_p0_userdebug_effect(
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
    canonical_request: &[u8],
) -> Result<P0UserdebugPreparedEffect> {
    if context.adapter()
        != trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi
    {
        return Err(DirectToolError::BackendUnavailable(
            "P0 userdebug tool-call transport permits only System API".to_string(),
        ));
    }
    let hello = P0UserdebugDirectOperationToolCallSessionHelloV1::derive(
        context.binding(),
        context.binding_sha256(),
        context.adapter(),
    )
    .map_err(protocol_error)?;
    prepare_p0_effect_with_hello(context, journal, canonical_request, &hello)
}

#[cfg(feature = "device-launch-package-conformance")]
pub(crate) struct P0UserdebugPreparedEffect {
    pub(crate) prepared: crate::operation_journal::PreparedOperation,
    stream: UnixStream,
    tool_call_commit: DirectOperationToolCallCommitReceiptV3,
}

#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn complete_p0_userdebug_effect(
    mut session: P0UserdebugPreparedEffect,
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<()> {
    let snapshot = journal
        .evidence_snapshot()
        .map_err(crate::journaled_call::journal_error)?;
    let disposition = DirectOperationAdapterTerminalDispositionV1 {
        schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
        binding_sha256: context.binding_sha256().to_string(),
        invocation_id: context.invocation_id().to_string(),
        delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
        provider_id: context.provider_id().to_string(),
        agent_id: context.agent_id().to_string(),
        adapter: context.adapter(),
        terminal_state: DirectOperationAdapterTerminalStateV1::Ackable {
            journal_evidence_snapshot: snapshot,
        },
    };
    disposition
        .validate_for_binding(context.binding(), context.adapter())
        .map_err(protocol_error)?;
    write_canonical_frame(&mut session.stream, &disposition)?;
    session.stream.shutdown(Shutdown::Write)?;
    let terminal_commit: P0UserdebugAdapterTerminalCommitV1 =
        read_canonical_frame(&mut session.stream)?;
    terminal_commit
        .validate_for(&session.tool_call_commit, &disposition)
        .map_err(protocol_error)?;
    require_peer_close(&mut session.stream)
}

#[cfg(feature = "device-launch-package-conformance")]
fn prepare_p0_effect_with_hello<T: Serialize>(
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
    canonical_request: &[u8],
    hello: &T,
) -> Result<P0UserdebugPreparedEffect> {
    let socket = Path::new(contract::SOCKET_ADDRESS);
    let mut stream = crate::uds::connect(socket)?;
    crate::uds::verify_connected_peer(
        socket,
        &stream,
        crate::uds::ExpectedBackendPeer::AgentDaemon,
    )?;
    stream.set_read_timeout(Some(SESSION_TIMEOUT))?;
    stream.set_write_timeout(Some(SESSION_TIMEOUT))?;
    write_canonical_frame(&mut stream, hello)?;
    let delivery: DirectOperationToolCallDeliveryV3 = read_canonical_frame(&mut stream)?;
    delivery
        .validate_for(
            context.binding(),
            context.binding_sha256(),
            context.adapter(),
        )
        .map_err(protocol_error)?;
    let allocation = DirectOperationToolCallAllocationRequestV3::derive(
        &delivery,
        context.binding(),
        context.binding_sha256(),
        context.adapter(),
        trillionnium_os_types::sha256_bytes(canonical_request),
    )
    .map_err(protocol_error)?;
    write_canonical_frame(&mut stream, &allocation)?;
    let envelope: DirectOperationToolCallEnvelopeV3 = read_canonical_frame(&mut stream)?;
    envelope
        .validate_for_allocation_request_v3(&allocation)
        .map_err(protocol_error)?;
    let prepared = journal
        .begin_effect_with_identity(
            &envelope.os_tool_call_id,
            envelope.adapter_effect_ordinal,
            canonical_request,
        )
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    let acknowledgement = journal
        .prepared_transport_ack(&envelope, &prepared)
        .map_err(crate::journaled_call::journal_error)?;
    write_canonical_frame(&mut stream, &acknowledgement)?;
    let tool_call_commit: DirectOperationToolCallCommitReceiptV3 =
        read_canonical_frame(&mut stream)?;
    tool_call_commit
        .validate_for_acknowledgement(&acknowledgement)
        .map_err(protocol_error)?;
    Ok(P0UserdebugPreparedEffect {
        prepared,
        stream,
        tool_call_commit,
    })
}

#[cfg(feature = "production-durable-hotpath")]
fn prepare_effect_with_hello<T: Serialize>(
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
    canonical_request: &[u8],
    hello: &T,
) -> Result<crate::operation_journal::PreparedOperation> {
    let socket = Path::new(contract::SOCKET_ADDRESS);
    let mut stream = crate::uds::connect(socket)?;
    crate::uds::verify_connected_peer(
        socket,
        &stream,
        crate::uds::ExpectedBackendPeer::AgentDaemon,
    )?;
    stream.set_read_timeout(Some(SESSION_TIMEOUT))?;
    stream.set_write_timeout(Some(SESSION_TIMEOUT))?;

    write_canonical_frame(&mut stream, hello)?;

    let delivery: DirectOperationToolCallDeliveryV3 = read_canonical_frame(&mut stream)?;
    delivery
        .validate_for(
            context.binding(),
            context.binding_sha256(),
            context.adapter(),
        )
        .map_err(protocol_error)?;
    let allocation = DirectOperationToolCallAllocationRequestV3::derive(
        &delivery,
        context.binding(),
        context.binding_sha256(),
        context.adapter(),
        trillionnium_os_types::sha256_bytes(canonical_request),
    )
    .map_err(protocol_error)?;
    write_canonical_frame(&mut stream, &allocation)?;

    let envelope: DirectOperationToolCallEnvelopeV3 = read_canonical_frame(&mut stream)?;
    envelope
        .validate_for_allocation_request_v3(&allocation)
        .map_err(protocol_error)?;
    let prepared = journal
        .begin_effect_with_identity(
            &envelope.os_tool_call_id,
            envelope.adapter_effect_ordinal,
            canonical_request,
        )
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    let acknowledgement = journal
        .prepared_transport_ack(&envelope, &prepared)
        .map_err(crate::journaled_call::journal_error)?;
    write_canonical_frame(&mut stream, &acknowledgement)?;
    stream.shutdown(Shutdown::Write)?;

    let receipt: DirectOperationToolCallCommitReceiptV3 = read_canonical_frame(&mut stream)?;
    receipt
        .validate_for_acknowledgement(&acknowledgement)
        .map_err(protocol_error)?;
    require_peer_close(&mut stream)?;
    Ok(prepared)
}

#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
fn write_canonical_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > contract::MAXIMUM_FRAME_BYTES {
        return Err(DirectToolError::BackendFailed(
            "Direct tool-call output frame is outside the fixed bound".to_string(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        DirectToolError::BackendFailed("Direct tool-call output length overflowed".to_string())
    })?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_canonical_frame<T: DeserializeOwned + Serialize>(stream: &mut UnixStream) -> Result<T> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "Direct tool-call response prefix is unavailable: {error}"
        ))
    })?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > contract::MAXIMUM_FRAME_BYTES {
        return Err(DirectToolError::BackendFailed(
            "Direct tool-call response frame is outside the fixed bound".to_string(),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "Direct tool-call response payload is incomplete: {error}"
        ))
    })?;
    let value: T = serde_json::from_slice(&payload).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "Direct tool-call response JSON is invalid: {error}"
        ))
    })?;
    if serde_json::to_vec(&value)? != payload {
        return Err(DirectToolError::BackendFailed(
            "Direct tool-call response is not canonical JSON".to_string(),
        ));
    }
    Ok(value)
}

fn require_peer_close(stream: &mut UnixStream) -> Result<()> {
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(DirectToolError::BackendFailed(
            "Direct tool-call daemon returned trailing bytes".to_string(),
        )),
        Err(error) => Err(DirectToolError::BackendFailed(format!(
            "Direct tool-call daemon did not close after its receipt: {error}"
        ))),
    }
}

#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
fn protocol_error(error: impl std::fmt::Display) -> DirectToolError {
    DirectToolError::BackendFailed(format!("Direct tool-call protocol binding failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    use trillionnium_os_types::direct_operation_tool_call_transport::{
        ADAPTER_CONNECTOR_PRODUCT_WIRED, CONFERS_EFFECT_AUTHORITY,
        FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE, PROVIDER_DELIVERY_PRODUCT_WIRED,
        ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE, SOCKET_NAME,
    };

    const _: () = {
        assert!(!ADAPTER_CONNECTOR_PRODUCT_WIRED);
        assert!(!PROVIDER_DELIVERY_PRODUCT_WIRED);
        assert!(!FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE);
        assert!(!ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    };

    #[test]
    fn fixed_socket_is_distinct_and_product_authority_flags_remain_false() {
        assert_eq!(contract::SOCKET_ADDRESS, format!("@{SOCKET_NAME}"));
        assert_ne!(
            contract::SOCKET_ADDRESS,
            crate::root_publication_transport::DEFAULT_SOCKET
        );
    }

    #[test]
    fn canonical_framing_rejects_noncanonical_json_and_trailing_receipt_bytes() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            let payload = br#"{ "value": 1 }"#;
            server
                .write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            server.write_all(payload).unwrap();
        });
        let error = read_canonical_frame::<serde_json::Value>(&mut client).unwrap_err();
        assert!(error.to_string().contains("not canonical"));
        writer.join().unwrap();

        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.write_all(b"x").unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        assert!(
            require_peer_close(&mut client)
                .unwrap_err()
                .to_string()
                .contains("trailing bytes")
        );
    }
}
