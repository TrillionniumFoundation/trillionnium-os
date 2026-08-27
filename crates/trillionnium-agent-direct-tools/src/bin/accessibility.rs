#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "development-compatibility-lane"
))]
use std::path::Path;

use trillionnium_agent_direct_tools::DirectToolError;
#[cfg(feature = "production-durable-hotpath")]
use trillionnium_agent_direct_tools::production_entry_hardening;
#[cfg(feature = "development-compatibility-lane")]
use trillionnium_agent_direct_tools::semantic_identity::{
    BackendRequestIdentityAuthor, EphemeralOsRequestIdentityAuthor,
};
#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "development-compatibility-lane"
))]
use trillionnium_agent_direct_tools::{
    accessibility, mcp, production_endpoint, read_request, trusted_context, write_response,
};
#[cfg(feature = "production-durable-hotpath")]
use trillionnium_os_types::direct_operation::DirectOperationAdapter;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(any(
    feature = "production-durable-hotpath",
    feature = "development-compatibility-lane"
)))]
fn run() -> trillionnium_agent_direct_tools::Result<()> {
    // The common product artifact is an inert, fail-closed ABI stub. Retain
    // the exact protocol and privacy-field markers so materialization can
    // prove which wire ABI is held without compiling the legacy inbox lane.
    Err(DirectToolError::BackendUnavailable(
        "Accessibility effect lane is not compiled; held ABI org.trillionnium.agent-accessibility.v2 requires snapshot_mode; product requires production-durable-hotpath and non-product development requires explicit development-compatibility-lane"
            .to_string(),
    ))
}

#[cfg(any(
    feature = "production-durable-hotpath",
    feature = "development-compatibility-lane"
))]
fn run() -> trillionnium_agent_direct_tools::Result<()> {
    // This is deliberately the first product action in Rust code. It closes
    // the exec-reset dumpability state and validates the inherited process
    // boundary before argv or stdin can influence this adapter.
    #[cfg(feature = "production-durable-hotpath")]
    let _entry_checkpoint = production_entry_hardening::enter_product_direct_tool_checkpoint(
        DirectOperationAdapter::Accessibility,
    )
    .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(feature = "production-durable-hotpath")]
    if arguments.is_empty() {
        return Err(DirectToolError::InvalidRequest(
            "raw backend-wire mode is non-product; use semantic or mcp".to_string(),
        ));
    }
    #[cfg(feature = "production-durable-hotpath")]
    let trusted_context = Some(
        trusted_context::TrustedAdapterContext::open_current_product(
            DirectOperationAdapter::Accessibility,
        )
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?,
    );
    #[cfg(feature = "development-compatibility-lane")]
    let trusted_context: Option<trusted_context::TrustedAdapterContext> = None;
    let socket = production_endpoint(
        accessibility::DEFAULT_SOCKET,
        "TRILLIONNIUM_ACCESSIBILITY_SOCKET",
    );
    match arguments.as_slice() {
        #[cfg(feature = "development-compatibility-lane")]
        [] => write_response(&call_backend(
            Path::new(&socket),
            &read_request()?,
            trusted_context.as_ref(),
        )?),
        [mode] if mode == "semantic" => {
            #[cfg(feature = "production-durable-hotpath")]
            {
                write_response(&call_semantic_backend(
                    Path::new(&socket),
                    &read_request()?,
                    trusted_context.as_ref(),
                )?)
            }
            #[cfg(feature = "development-compatibility-lane")]
            {
                let mut author = EphemeralOsRequestIdentityAuthor::from_kernel()?;
                write_response(&call_semantic_backend(
                    Path::new(&socket),
                    &read_request()?,
                    trusted_context.as_ref(),
                    &mut author,
                )?)
            }
        }
        [mode] if mode == "mcp" => {
            #[cfg(feature = "production-durable-hotpath")]
            {
                mcp::serve_stdio(
                    "trillionnium-agent-accessibility",
                    accessibility::mcp_tool(),
                    |arguments| {
                        let request = serde_json::from_value(arguments)?;
                        call_semantic_backend(
                            Path::new(&socket),
                            &request,
                            trusted_context.as_ref(),
                        )
                    },
                )
            }
            #[cfg(feature = "development-compatibility-lane")]
            {
                let mut author = EphemeralOsRequestIdentityAuthor::from_kernel()?;
                mcp::serve_stdio(
                    "trillionnium-agent-accessibility",
                    accessibility::mcp_tool(),
                    |arguments| {
                        let request = serde_json::from_value(arguments)?;
                        call_semantic_backend(
                            Path::new(&socket),
                            &request,
                            trusted_context.as_ref(),
                            &mut author,
                        )
                    },
                )
            }
        }
        _ => Err(DirectToolError::InvalidRequest(
            "usage: trillionnium-agent-accessibility [semantic|mcp]".to_string(),
        )),
    }
}

#[cfg(feature = "development-compatibility-lane")]
fn call_backend(
    socket: &Path,
    request: &accessibility::AccessibilityRequest,
    context: Option<&trusted_context::TrustedAdapterContext>,
) -> trillionnium_agent_direct_tools::Result<serde_json::Value> {
    let _ = context;
    accessibility::call(socket, request)
}

#[cfg(feature = "production-durable-hotpath")]
fn call_semantic_backend(
    socket: &Path,
    request: &accessibility::AccessibilitySemanticRequest,
    context: Option<&trusted_context::TrustedAdapterContext>,
) -> trillionnium_agent_direct_tools::Result<serde_json::Value> {
    let context = context.ok_or_else(|| {
        DirectToolError::BackendUnavailable(
            "trusted Accessibility launch context is unavailable".to_string(),
        )
    })?;
    accessibility::call_semantic_trusted(socket, request, context)
}

#[cfg(feature = "development-compatibility-lane")]
fn call_semantic_backend(
    socket: &Path,
    request: &accessibility::AccessibilitySemanticRequest,
    context: Option<&trusted_context::TrustedAdapterContext>,
    author: &mut impl BackendRequestIdentityAuthor,
) -> trillionnium_agent_direct_tools::Result<serde_json::Value> {
    let _ = context;
    accessibility::call_semantic(socket, request, author)
}
