//! MCP tools and resources over the Quarters core authority.

use std::borrow::Cow;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use quarters_core::{
    EnvironmentPlan, ErrorKind, HostEnvironment, LeaseState, QuartersError, RollbackObservation, Space,
    SpaceInspection, SpaceName, Store,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CacheScope, DiscoverResult, Implementation, InitializeRequestParams, InitializeResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams,
    ReadResourceResponse, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use tokio::sync::Semaphore;

use crate::model::{
    CapabilityView, CreateData, Diagnostic, DoctorData, ProbeView, RollbackIssueView, SpaceView, StatusData,
};
use crate::output::{ToolSuccess, failure, success};
use crate::params::{CreateParams, DoctorParams, MAX_STATUS_ENTRIES, StatusParams};
use crate::resources;

/// MCP revisions intentionally implemented and tested by Quarters.
pub const SUPPORTED_PROTOCOL_VERSIONS: [ProtocolVersion; 2] =
    [ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25];

const MAX_BLOCKING_STORE_CALLS: usize = 2;

/// Agent-native adapter over one folder-backed Quarters store.
#[derive(Debug, Clone)]
pub(crate) struct QuartersMcp {
    store: Store,
    host: HostEnvironment,
    command_launcher: Option<PathBuf>,
    tool_router: ToolRouter<Self>,
    blocking_slots: Arc<Semaphore>,
}

impl QuartersMcp {
    pub(crate) fn new(store: Store, host: HostEnvironment, command_launcher: Option<PathBuf>) -> Self {
        Self {
            store,
            host,
            command_launcher,
            tool_router: Self::tool_router(),
            blocking_slots: Arc::new(Semaphore::new(MAX_BLOCKING_STORE_CALLS)),
        }
    }

    async fn run_blocking<T, F>(&self, operation: F) -> quarters_core::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> quarters_core::Result<T> + Send + 'static,
    {
        let permit = self.blocking_slots.clone().acquire_owned().await.map_err(|_error| {
            QuartersError::new(ErrorKind::System, "the MCP filesystem work queue closed unexpectedly")
        })?;
        let server = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(server)
        })
        .await
        .map_err(|_error| QuartersError::new(ErrorKind::System, "an MCP filesystem worker ended unexpectedly"))?
    }

    fn status_data(&self, raw_name: Option<&str>) -> quarters_core::Result<StatusData> {
        let unfiltered = raw_name.is_none();
        let inspections = if let Some(raw_name) = raw_name {
            let name = SpaceName::parse(raw_name.to_owned())?;
            vec![self.store.inspect_named(&name)?]
        } else {
            self.store.inspect_at_most(MAX_STATUS_ENTRIES)?
        };
        let current_space = validated_current_space(&self.store, &self.host);
        let healthy_spaces = inspections
            .iter()
            .filter_map(|inspection| match inspection {
                SpaceInspection::Healthy(space) => Some(space),
                SpaceInspection::Unhealthy { .. } => None,
            })
            .collect::<Vec<_>>();
        let mut lease_states = self.store.lease_states(&healthy_spaces)?.into_iter();
        let mut spaces = Vec::with_capacity(inspections.len());
        for inspection in inspections {
            let lease_state = match inspection {
                SpaceInspection::Healthy(space) => {
                    let state = lease_states.next().ok_or_else(|| {
                        QuartersError::new(
                            quarters_core::ErrorKind::System,
                            "activity observation returned too few states",
                        )
                    })?;
                    self.view_space(&space, state, current_space.as_deref(), !unfiltered)?
                }
                unhealthy @ SpaceInspection::Unhealthy { .. } => {
                    Self::view_inspection(unhealthy, current_space.as_deref())?
                }
            };
            spaces.push(lease_state);
        }
        let mut rollback_issues = Vec::new();
        if unfiltered {
            let rollback_inventory = self.store.rollback_inventory()?;
            let rollbacks = rollback_inventory.observations;
            let issues = rollback_inventory.issues;
            spaces.retain(|space| {
                !rollbacks.iter().any(|rollback| rollback.target.as_str() == space.name)
                    && !issues.iter().any(|issue| {
                        issue
                            .target
                            .as_ref()
                            .is_some_and(|target| target.as_str() == space.name)
                    })
            });
            spaces.extend(rollbacks.iter().map(Self::view_rollback));
            let mut represented_targets = rollbacks
                .iter()
                .map(|rollback| rollback.target.clone())
                .collect::<std::collections::BTreeSet<_>>();
            spaces.extend(issues.iter().filter_map(|issue| {
                let target = issue.target.as_ref()?;
                represented_targets
                    .insert(target.clone())
                    .then(|| Self::view_rollback_issue(issue))
                    .flatten()
            }));
            rollback_issues = issues.iter().map(RollbackIssueView::from).collect();
            spaces.sort_by(|left, right| left.name.cmp(&right.name));
            enforce_status_budget(spaces.len(), rollback_issues.len())?;
        }
        Ok(StatusData {
            observation_scope: "quarters-cooperative-lease".to_owned(),
            detached_processes: "unknown".to_owned(),
            current_space,
            spaces,
            rollback_issues,
        })
    }

    fn view_inspection(inspection: SpaceInspection, current_space: Option<&str>) -> quarters_core::Result<SpaceView> {
        match inspection {
            SpaceInspection::Healthy(_space) => Err(QuartersError::new(
                quarters_core::ErrorKind::System,
                "healthy space reached the unhealthy-entry presenter",
            )),
            SpaceInspection::Unhealthy {
                name,
                name_was_lossy,
                error,
            } => Ok(SpaceView {
                current: current_space == Some(name.as_str()),
                name: quarters_core::encode_untrusted_text_hex_bounded(&name, 64),
                health: "unhealthy".to_owned(),
                state: None,
                name_trust: "untrusted_directory_entry".to_owned(),
                name_encoding: if name_was_lossy {
                    "lossy_replacement_hex".to_owned()
                } else {
                    "utf8_hex".to_owned()
                },
                home: None,
                created_unix_ms: None,
                default_shell: None,
                layout: None,
                space_id: None,
                lease_state: None,
                ssh_agent_state: None,
                issue: Some(Diagnostic::for_unhealthy_entry(&error)),
            }),
        }
    }

    fn view_rollback(observation: &RollbackObservation) -> SpaceView {
        let error = QuartersError::new(
            ErrorKind::SpaceActive,
            format!("space '{}' has a rollback in progress", observation.target),
        );
        SpaceView {
            name: observation.target.as_str().to_owned(),
            health: "unhealthy".to_owned(),
            state: Some("rollback_in_progress".to_owned()),
            name_trust: "validated_manifest_name".to_owned(),
            name_encoding: "utf8".to_owned(),
            home: None,
            created_unix_ms: None,
            default_shell: None,
            layout: None,
            space_id: None,
            lease_state: None,
            ssh_agent_state: None,
            current: false,
            issue: Some(Diagnostic::from(&error)),
        }
    }

    fn view_rollback_issue(issue: &quarters_core::RollbackIssue) -> Option<SpaceView> {
        let target = issue.target.as_ref()?;
        Some(SpaceView {
            name: target.as_str().to_owned(),
            health: "unhealthy".to_owned(),
            state: Some("rollback_issue".to_owned()),
            name_trust: "validated_manifest_name".to_owned(),
            name_encoding: "utf8".to_owned(),
            home: None,
            created_unix_ms: None,
            default_shell: None,
            layout: None,
            space_id: None,
            lease_state: None,
            ssh_agent_state: None,
            current: false,
            issue: Some(Diagnostic {
                code: issue.code.clone(),
                message: quarters_core::escape_untrusted_text_bounded(&issue.message, 512),
                retryable: false,
                hint: None,
            }),
        })
    }

    fn doctor_data(&self, raw_name: Option<&str>) -> quarters_core::Result<DoctorData> {
        let validated_space = raw_name
            .map(|raw_name| self.validate_space_environment(raw_name))
            .transpose()?;
        let platform = quarters_core::platform::capabilities();
        let capabilities = capability_views(&platform);
        Ok(DoctorData {
            platform: platform.platform,
            authority_boundary: platform.authority_boundary,
            capabilities,
            tools: quarters_core::tool_probes().into_iter().map(ProbeView::from).collect(),
            validated_space,
        })
    }

    fn validate_space_environment(&self, raw_name: &str) -> quarters_core::Result<String> {
        let name = SpaceName::parse(raw_name.to_owned())?;
        let space = self.store.open(&name)?;
        EnvironmentPlan::for_space(&space, &self.host, &space.home(), &[])?;
        Ok(name.as_str().to_owned())
    }

    fn create_space(
        &self,
        raw_name: String,
        layout: Option<crate::params::CreateLayout>,
    ) -> quarters_core::Result<CreateData> {
        let name = SpaceName::parse(raw_name)?;
        let shell = self
            .host
            .get("SHELL")
            .map_or_else(|| PathBuf::from("/bin/sh"), PathBuf::from);
        let layout = layout.map_or(quarters_core::SpaceLayout::Profile, Into::into);
        let space = self.store.create_with_layout(name, shell, layout)?;
        self.install_created_command_links(&space)?;
        Ok(CreateData {
            space: self.view_space(
                &space,
                LeaseState::Free,
                validated_current_space(&self.store, &self.host).as_deref(),
                true,
            )?,
        })
    }

    fn install_created_command_links(&self, space: &Space) -> quarters_core::Result<()> {
        let Some(executable) = &self.command_launcher else {
            return Ok(());
        };
        self.store
            .install_space_command_links(&space.manifest().name, executable)
            .map(|_report| ())
            .map_err(|error| {
                error.with_hint(format!(
                    "space '{}' was published, but managed commands are incomplete; inspect it with the Quarters CLI",
                    space.manifest().name
                ))
            })
    }

    fn view_space(
        &self,
        space: &Space,
        lease_state: LeaseState,
        current_space: Option<&str>,
        inspect_agent: bool,
    ) -> quarters_core::Result<SpaceView> {
        let mut view = view_space(space, lease_state, current_space)?;
        view.ssh_agent_state = Some(if inspect_agent {
            self.store.ssh_agent_status(space, &self.host).map_or_else(
                |_error| "unavailable".to_owned(),
                |status| status.state.as_str().to_owned(),
            )
        } else {
            "not-inspected".to_owned()
        });
        Ok(view)
    }
}

fn enforce_status_budget(space_entries: usize, rollback_issues: usize) -> quarters_core::Result<()> {
    if space_entries.saturating_add(rollback_issues) <= MAX_STATUS_ENTRIES {
        return Ok(());
    }
    Err(QuartersError::new(
        ErrorKind::ResourceLimit,
        format!("the complete MCP status contains more than {MAX_STATUS_ENTRIES} entries"),
    )
    .with_hint("inspect one exact space by name, or use the human CLI outside an MCP transcript"))
}

#[tool_router]
impl QuartersMcp {
    /// Read bounded space health, metadata and cooperative lease state without executing tools.
    #[tool(
        name = "quarters_status",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<StatusData>>(),
        annotations(
            title = "Quarters status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn status(
        &self,
        Parameters(params): Parameters<StatusParams>,
    ) -> Result<ToolSuccess<StatusData>, rmcp::model::CallToolResult> {
        let name = params.name;
        let data = self
            .run_blocking(move |server| server.status_data(name.as_deref()))
            .await
            .map_err(|error| failure(&error))?;
        Ok(success(
            format!("Inspected {} Quarters space entries.", data.spaces.len()),
            data,
        ))
    }

    /// Inspect platform and tool compatibility; a named check prepares private runtime paths.
    #[tool(
        name = "quarters_doctor",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<DoctorData>>(),
        annotations(
            title = "Quarters doctor",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn doctor(
        &self,
        Parameters(params): Parameters<DoctorParams>,
    ) -> Result<ToolSuccess<DoctorData>, rmcp::model::CallToolResult> {
        let name = params.name;
        let data = self
            .run_blocking(move |server| server.doctor_data(name.as_deref()))
            .await
            .map_err(|error| failure(&error))?;
        let summary = data.validated_space.as_ref().map_or_else(
            || "Inspected Quarters capabilities without executing installed tools.".to_owned(),
            |name| format!("Validated the environment and runtime paths for '{name}'."),
        );
        Ok(success(summary, data))
    }

    /// Create one private folder-backed space without launching a shell or command.
    #[tool(
        name = "quarters_create",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<CreateData>>(),
        annotations(
            title = "Create Quarters space",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn create(
        &self,
        Parameters(params): Parameters<CreateParams>,
    ) -> Result<ToolSuccess<CreateData>, rmcp::model::CallToolResult> {
        let data = self
            .run_blocking(move |server| server.create_space(params.name, params.layout))
            .await
            .map_err(|error| failure(&error))?;
        Ok(success(format!("Created space '{}'.", data.space.name), data))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for QuartersMcp {
    fn discover(
        &self,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(DiscoverResult::from_server_info(
            vec![ProtocolVersion::V_2026_07_28],
            self.get_info(),
        )))
    }

    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + Send + '_ {
        let mut info = self.get_info();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        std::future::ready(Ok(info))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn get_info(&self) -> ServerInfo {
        let capabilities = ServerCapabilities::builder().enable_resources().enable_tools().build();
        ServerInfo::new(capabilities)
            .with_server_info(server_implementation())
            .with_instructions(
                "Read quarters://help and quarters://security first. Observe quarters_status before mutation. Quarters virtualizes user-owned state but preserves the host account's real authority.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let result = ListToolsResult::with_all_items(self.tool_router.list_all());
        if supports_cache_hints(&context) {
            Ok(result.with_ttl_ms(3_600_000).with_cache_scope(CacheScope::Public))
        } else {
            Ok(result)
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(resources::list(supports_cache_hints(&context)))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::default())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let cache_hints = supports_cache_hints(&context);
        if let Some(resource) = resources::read_static(&request.uri, cache_hints) {
            return Ok(resource);
        }
        if request.uri == resources::STATUS_URI {
            let status = self
                .run_blocking(|server| server.status_data(None))
                .await
                .map_err(|error| core_resource_error(&error))?;
            return resources::private_json(resources::STATUS_URI, &status, cache_hints);
        }
        Err(ErrorData::resource_not_found("unknown Quarters resource", None))
    }
}

pub(crate) fn server_implementation() -> Implementation {
    Implementation::new("quarters", env!("CARGO_PKG_VERSION"))
        .with_title("Quarters")
        .with_description("Persistent alternate user-state spaces for native processes")
        .with_website_url("https://github.com/agenxy/quarters")
}

fn view_space(space: &Space, lease_state: LeaseState, current_space: Option<&str>) -> quarters_core::Result<SpaceView> {
    let created_unix_ms = u64::try_from(space.manifest().created_unix_ms).map_err(|_error| {
        QuartersError::new(
            ErrorKind::CorruptState,
            "space creation time cannot be represented by the MCP contract",
        )
    })?;
    Ok(SpaceView {
        name: space.manifest().name.as_str().to_owned(),
        health: "healthy".to_owned(),
        state: None,
        name_trust: "validated_space_name".to_owned(),
        name_encoding: "utf8_validated".to_owned(),
        home: Some(quarters_core::escape_untrusted_text_bounded(
            &space.home().to_string_lossy(),
            512,
        )),
        created_unix_ms: Some(created_unix_ms),
        default_shell: Some(quarters_core::escape_untrusted_text_bounded(
            &space.manifest().default_shell.to_string_lossy(),
            512,
        )),
        layout: Some(space.layout().as_str().to_owned()),
        space_id: space.id().map(|space_id| space_id.as_str().to_owned()),
        lease_state: Some(lease_state.as_str().to_owned()),
        ssh_agent_state: None,
        current: current_space == Some(space.manifest().name.as_str()),
        issue: None,
    })
}

fn validated_current_space(store: &Store, host: &HostEnvironment) -> Option<String> {
    let candidate = SpaceName::parse(host.get("QUARTERS_SPACE")?.to_str()?.to_owned()).ok()?;
    match store.inspect_named(&candidate).ok()? {
        SpaceInspection::Healthy(_space) => Some(candidate.as_str().to_owned()),
        SpaceInspection::Unhealthy { .. } => None,
    }
}

fn capability_views(platform: &quarters_core::Capabilities) -> Vec<CapabilityView> {
    vec![
        CapabilityView {
            name: "environment_profile".to_owned(),
            available: platform.environment_profile,
            status: "stable".to_owned(),
            detail: "HOME, XDG and documented tool-state overrides".to_owned(),
        },
        CapabilityView {
            name: "core_foundation_home".to_owned(),
            available: platform.core_foundation_home,
            status: if platform.core_foundation_home {
                "best-effort".to_owned()
            } else {
                "unavailable".to_owned()
            },
            detail: "CFFIXED_USER_HOME compatibility on macOS".to_owned(),
        },
        CapabilityView {
            name: "workspace_profile".to_owned(),
            available: platform.workspace_profile.available,
            status: platform.workspace_profile.status.clone(),
            detail: platform.workspace_profile.detail.clone(),
        },
        CapabilityView {
            name: "home_view".to_owned(),
            available: platform.home_view.available,
            status: platform.home_view.status.clone(),
            detail: platform.home_view.detail.clone(),
        },
        CapabilityView {
            name: "confinement".to_owned(),
            available: platform.confinement.available,
            status: platform.confinement.status.clone(),
            detail: platform.confinement.detail.clone(),
        },
    ]
}

fn supports_cache_hints(context: &RequestContext<rmcp::RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

fn core_resource_error(error: &QuartersError) -> ErrorData {
    let diagnostic = Diagnostic::from(error);
    ErrorData::internal_error(diagnostic.message.clone(), serde_json::to_value(diagnostic).ok())
}
