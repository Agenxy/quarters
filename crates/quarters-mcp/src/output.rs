//! Bounded, dual-carrier MCP tool results.

use std::borrow::Cow;

use quarters_core::QuartersError;
use rmcp::ErrorData;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;

use crate::model::Diagnostic;

const MAX_TOOL_RESULT_BYTES: usize = crate::transport::MAX_MCP_MESSAGE_BYTES - 16 * 1_024;

/// Stable structured envelope returned by a successful Quarters tool.
#[derive(Debug, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolOutput<T> {
    /// Concise transcript outcome.
    pub(crate) summary: String,
    /// Typed machine-readable result.
    pub(crate) data: T,
}

/// Successful result with equivalent text and structured carriers.
pub(crate) struct ToolSuccess<T>(ToolOutput<T>);

impl<T: JsonSchema> JsonSchema for ToolSuccess<T> {
    fn schema_name() -> Cow<'static, str> {
        ToolOutput::<T>::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "oneOf": [
                generator.subschema_for::<ToolOutput<T>>(),
                generator.subschema_for::<Diagnostic>()
            ]
        })
    }
}

impl<T> IntoCallToolResult for ToolSuccess<T>
where
    T: Serialize + JsonSchema + 'static,
{
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        let summary = self.0.summary.clone();
        let value = serde_json::to_value(self.0)
            .map_err(|_error| ErrorData::internal_error("could not encode the Quarters tool result", None))?;
        let detail = serde_json::to_string(&value["data"])
            .map_err(|_error| ErrorData::internal_error("could not encode the Quarters transcript result", None))?;
        let mut result = CallToolResult::success(vec![ContentBlock::text(format!("{summary}\n\n{detail}"))]);
        result.structured_content = Some(value);
        if encoded_too_large(&result) {
            return Ok(resource_limit_failure().into());
        }
        Ok(result.into())
    }
}

pub(crate) fn success<T>(summary: impl Into<String>, data: T) -> ToolSuccess<T> {
    ToolSuccess(ToolOutput {
        summary: summary.into(),
        data,
    })
}

pub(crate) fn failure(error: &QuartersError) -> CallToolResult {
    let diagnostic = Diagnostic::from(error);
    diagnostic_failure(&diagnostic)
}

fn diagnostic_failure(diagnostic: &Diagnostic) -> CallToolResult {
    let value = serde_json::to_value(diagnostic).unwrap_or_else(|_error| {
        serde_json::json!({
            "code": "system",
            "message": "could not encode a Quarters failure",
            "retryable": false
        })
    });
    let detail = serde_json::to_string(&value).unwrap_or_else(|_error| "{}".to_owned());
    let mut result = CallToolResult::error(vec![ContentBlock::text(format!("{}\n\n{detail}", diagnostic.message))]);
    result.structured_content = Some(value);
    result
}

fn encoded_too_large(result: &CallToolResult) -> bool {
    serde_json::to_vec(result).map_or(true, |encoded| encoded.len() > MAX_TOOL_RESULT_BYTES)
}

fn resource_limit_failure() -> CallToolResult {
    diagnostic_failure(&Diagnostic {
        code: "resource_limit".to_owned(),
        message: "the complete tool result exceeded Quarters' bounded MCP response budget".to_owned(),
        retryable: false,
        hint: None,
    })
}
