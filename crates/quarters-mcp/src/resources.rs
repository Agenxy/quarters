//! Fixed MCP resource catalog and revision-aware cache policy.

use rmcp::ErrorData;
use rmcp::model::{
    CacheScope, ListResourcesResult, ReadResourceResponse, ReadResourceResult, Resource, ResourceContents,
};
use serde::Serialize;

pub(crate) const HELP_URI: &str = "quarters://help";
pub(crate) const SECURITY_URI: &str = "quarters://security";
pub(crate) const STATUS_URI: &str = "quarters://status";

const STATIC_TTL_MS: u64 = 3_600_000;
const STATE_TTL_MS: u64 = 500;
const HELP: &str = include_str!("guidance.md");
const SECURITY: &str = include_str!("security.md");

pub(crate) fn list(cache_hints: bool) -> ListResourcesResult {
    let resources = vec![
        resource(
            HELP_URI,
            "help",
            "Agent workflow and safe operating boundary",
            "text/markdown",
        ),
        resource(
            SECURITY_URI,
            "security",
            "Authority, privacy and threat boundary",
            "text/markdown",
        ),
        resource(
            STATUS_URI,
            "status",
            "Bounded current space health and cooperative lease state",
            "application/json",
        ),
    ];
    let result = ListResourcesResult::with_all_items(resources);
    with_list_cache(result, cache_hints)
}

pub(crate) fn read_static(uri: &str, cache_hints: bool) -> Option<ReadResourceResponse> {
    match uri {
        HELP_URI => Some(static_text(HELP_URI, HELP, cache_hints)),
        SECURITY_URI => Some(static_text(SECURITY_URI, SECURITY, cache_hints)),
        _ => None,
    }
}

pub(crate) fn private_json<T>(uri: &str, value: &T, cache_hints: bool) -> Result<ReadResourceResponse, ErrorData>
where
    T: Serialize,
{
    let text = serde_json::to_string(value)
        .map_err(|_error| ErrorData::internal_error("could not encode a Quarters resource", None))?;
    let result = ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type("application/json"),
    ]);
    Ok(with_read_cache(result, cache_hints, STATE_TTL_MS, CacheScope::Private).into())
}

fn resource(uri: &str, name: &str, description: &str, mime: &str) -> Resource {
    Resource::new(uri, name)
        .with_title(format!("Quarters {name}"))
        .with_description(description)
        .with_mime_type(mime)
}

fn static_text(uri: &str, text: &str, cache_hints: bool) -> ReadResourceResponse {
    let result = ReadResourceResult::new(vec![ResourceContents::text(text, uri).with_mime_type("text/markdown")]);
    with_read_cache(result, cache_hints, STATIC_TTL_MS, CacheScope::Public).into()
}

fn with_list_cache(result: ListResourcesResult, enabled: bool) -> ListResourcesResult {
    if enabled {
        result.with_ttl_ms(STATIC_TTL_MS).with_cache_scope(CacheScope::Public)
    } else {
        result
    }
}

fn with_read_cache(result: ReadResourceResult, enabled: bool, ttl_ms: u64, scope: CacheScope) -> ReadResourceResult {
    if enabled {
        result.with_ttl_ms(ttl_ms).with_cache_scope(scope)
    } else {
        result
    }
}
