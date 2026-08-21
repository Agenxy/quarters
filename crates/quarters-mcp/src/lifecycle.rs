//! Connection-family isolation, cancellation and bounded request admission.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use quarters_core::{HostEnvironment, Store};
use rmcp::model::{ClientRequest, ErrorData, ProtocolVersion, RequestId, ServerInfo, ServerResult};
use rmcp::service::{RequestContext, RoleServer, Service};

use crate::server::QuartersMcp;

const INITIALIZE_PROTOCOL_VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::V_2025_11_25];

/// Maximum requests retained until their responses finish writing.
pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 32;
/// Maximum distinct request identifiers retained for one legacy session.
pub(crate) const MAX_SESSION_REQUEST_IDS: usize = 8_192;
const MAX_REQUEST_ID_BYTES: usize = 128;

/// MCP service wrapper that keeps 2026 and 2025 lifecycle families disjoint.
#[derive(Debug, Clone)]
pub(crate) struct QuartersService {
    inner: QuartersMcp,
    family: ProtocolFamily,
    admission: RequestAdmission,
}

impl QuartersService {
    pub(crate) fn with_controls(
        store: Store,
        host: HostEnvironment,
        family: ProtocolFamily,
        admission: RequestAdmission,
    ) -> Self {
        Self {
            inner: QuartersMcp::new(store, host),
            family,
            admission,
        }
    }
}

impl Service<RoleServer> for QuartersService {
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        self.family.validate(&request, &context, &self.admission)?;
        let _request_guard = self.admission.claim(context.id.clone())?;
        Service::<RoleServer>::handle_request(&self.inner, request, context).await
    }

    fn handle_notification(
        &self,
        notification: rmcp::model::ClientNotification,
        context: rmcp::service::NotificationContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        Service::<RoleServer>::handle_notification(&self.inner, notification, context)
    }

    fn get_info(&self) -> ServerInfo {
        Service::<RoleServer>::get_info(&self.inner)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&INITIALIZE_PROTOCOL_VERSIONS)
    }
}

fn request_capacity_error() -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode(-30_001),
        "MCP request capacity reached",
        Some(serde_json::json!({"limit": MAX_IN_FLIGHT_REQUESTS})),
    )
}

fn duplicate_request_error() -> ErrorData {
    ErrorData::invalid_request("JSON-RPC request id was already used in this session", None)
}

fn request_id_limit_error() -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode(-30_003),
        "MCP session request-id capacity reached",
        Some(serde_json::json!({"limit": MAX_SESSION_REQUEST_IDS})),
    )
}

fn request_id_length_error() -> ErrorData {
    ErrorData::invalid_request(
        format!("String request ids may contain at most {MAX_REQUEST_ID_BYTES} UTF-8 bytes"),
        None,
    )
}

#[derive(Debug, Clone)]
pub(crate) struct RequestAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

#[derive(Debug, Default)]
struct AdmissionState {
    requests: HashMap<RequestId, RequestState>,
    seen: HashSet<RequestId>,
    legacy: bool,
}

#[derive(Debug)]
struct RequestState {
    phase: RequestPhase,
    transport_owned: bool,
    cancelled: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RequestPhase {
    Reserved,
    Running,
    HandlerDone,
    ResponseStarted,
}

impl Default for RequestState {
    fn default() -> Self {
        Self {
            phase: RequestPhase::Reserved,
            transport_owned: true,
            cancelled: false,
        }
    }
}

impl RequestAdmission {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState::default())),
        }
    }

    pub(crate) fn reserve(&self, id: RequestId) -> Result<(), AdmissionFailure> {
        let mut state = self.lock();
        validate_request_id(&id).map_err(|()| AdmissionFailure::IdTooLong)?;
        if state.requests.contains_key(&id) || (state.legacy && state.seen.contains(&id)) {
            return Err(AdmissionFailure::Duplicate);
        }
        if state.legacy && state.seen.len() >= MAX_SESSION_REQUEST_IDS {
            return Err(AdmissionFailure::SessionLimit);
        }
        if state.legacy {
            state.seen.insert(id.clone());
        }
        if state.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            return Err(AdmissionFailure::Capacity);
        }
        state.requests.insert(id, RequestState::default());
        Ok(())
    }

    fn claim(&self, id: RequestId) -> Result<RequestGuard, ErrorData> {
        let mut state = self.lock();
        if let Some(request) = state.requests.get_mut(&id) {
            if request.phase != RequestPhase::Reserved {
                return Err(duplicate_request_error());
            }
            request.phase = RequestPhase::Running;
        } else {
            validate_request_id(&id).map_err(|()| request_id_length_error())?;
            if state.legacy && state.seen.contains(&id) {
                return Err(duplicate_request_error());
            }
            if state.legacy && state.seen.len() >= MAX_SESSION_REQUEST_IDS {
                return Err(request_id_limit_error());
            }
            if state.legacy {
                state.seen.insert(id.clone());
            }
            if state.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
                return Err(request_capacity_error());
            }
            state.requests.insert(
                id.clone(),
                RequestState {
                    phase: RequestPhase::Running,
                    transport_owned: false,
                    cancelled: false,
                },
            );
        }
        Ok(RequestGuard {
            admission: self.clone(),
            id: Some(id),
        })
    }

    pub(crate) fn start_response(&self, id: &RequestId) {
        if let Some(request) = self.lock().requests.get_mut(id) {
            request.phase = RequestPhase::ResponseStarted;
        }
    }

    pub(crate) fn finish_response(&self, id: &RequestId) {
        self.lock().requests.remove(id);
    }

    pub(crate) fn close(&self) {
        let mut state = self.lock();
        state.requests.clear();
        state.seen.clear();
        state.legacy = false;
    }

    pub(crate) fn cancel(&self, id: &RequestId) {
        let mut state = self.lock();
        let handler_done = state.requests.get_mut(id).is_some_and(|request| {
            request.cancelled = true;
            request.phase == RequestPhase::HandlerDone
        });
        if handler_done {
            state.requests.remove(id);
        }
    }

    fn enter_legacy(&self) {
        let mut state = self.lock();
        state.legacy = true;
        let active = state.requests.keys().cloned().collect::<Vec<_>>();
        state.seen.extend(active);
    }

    fn finish_handler(&self, id: &RequestId) {
        let mut state = self.lock();
        let remove = state.requests.get_mut(id).is_some_and(|request| {
            let response_started = request.phase == RequestPhase::ResponseStarted;
            if !response_started {
                request.phase = RequestPhase::HandlerDone;
            }
            !request.transport_owned || (request.cancelled && !response_started)
        });
        if remove {
            state.requests.remove(id);
        }
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.lock().requests.len()
    }

    fn lock(&self) -> MutexGuard<'_, AdmissionState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AdmissionFailure {
    Duplicate,
    Capacity,
    SessionLimit,
    IdTooLong,
}

impl AdmissionFailure {
    pub(crate) fn error(self) -> ErrorData {
        match self {
            Self::Duplicate => duplicate_request_error(),
            Self::Capacity => request_capacity_error(),
            Self::SessionLimit => request_id_limit_error(),
            Self::IdTooLong => request_id_length_error(),
        }
    }
}

fn validate_request_id(id: &RequestId) -> Result<(), ()> {
    match id {
        RequestId::String(value) if value.len() > MAX_REQUEST_ID_BYTES => Err(()),
        _ => Ok(()),
    }
}

#[derive(Debug)]
struct RequestGuard {
    admission: RequestAdmission,
    id: Option<RequestId>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.admission.finish_handler(&id);
        }
    }
}

/// Shared protocol-family state used by the service and bounded transport.
#[derive(Debug, Clone)]
pub(crate) struct ProtocolFamily {
    state: Arc<Mutex<FamilyState>>,
}

impl ProtocolFamily {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FamilyState::Unopened)),
        }
    }

    pub(crate) fn is_legacy(&self) -> bool {
        *self.lock() == FamilyState::Legacy
    }

    pub(crate) fn is_modern(&self) -> bool {
        *self.lock() == FamilyState::Modern
    }

    pub(crate) fn is_unopened(&self) -> bool {
        *self.lock() == FamilyState::Unopened
    }

    fn validate(
        &self,
        request: &ClientRequest,
        context: &RequestContext<RoleServer>,
        admission: &RequestAdmission,
    ) -> Result<(), ErrorData> {
        let mut state = self.lock();
        let opening_legacy = matches!(request, ClientRequest::InitializeRequest(_));
        let expected = expected_version(*state, opening_legacy);
        validate_family_method(request, *state, &expected)?;
        if let Some(requested) = context.meta.protocol_version()
            && requested != expected
        {
            return Err(ErrorData::unsupported_protocol_version(
                requested,
                std::slice::from_ref(&expected),
            ));
        }
        if opening_legacy {
            admission.enter_legacy();
            *state = FamilyState::Legacy;
        } else if *state == FamilyState::Unopened {
            *state = FamilyState::Modern;
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, FamilyState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn expected_version(state: FamilyState, opening_legacy: bool) -> ProtocolVersion {
    match state {
        FamilyState::Unopened if opening_legacy => ProtocolVersion::V_2025_11_25,
        FamilyState::Legacy => ProtocolVersion::V_2025_11_25,
        FamilyState::Unopened | FamilyState::Modern => ProtocolVersion::V_2026_07_28,
    }
}

fn validate_family_method(
    request: &ClientRequest,
    state: FamilyState,
    expected: &ProtocolVersion,
) -> Result<(), ErrorData> {
    if state != FamilyState::Unopened && matches!(request, ClientRequest::InitializeRequest(_)) {
        return Err(method_not_found(expected));
    }
    let cross_family = if *expected == ProtocolVersion::V_2025_11_25 {
        matches!(
            request,
            ClientRequest::DiscoverRequest(_)
                | ClientRequest::SubscriptionsListenRequest(_)
                | ClientRequest::GetTaskRequest(_)
                | ClientRequest::UpdateTaskRequest(_)
                | ClientRequest::CancelTaskRequest(_)
        )
    } else {
        matches!(
            request,
            ClientRequest::PingRequest(_) | ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)
        )
    };
    if cross_family {
        Err(method_not_found(expected))
    } else {
        Ok(())
    }
}

fn method_not_found(expected: &ProtocolVersion) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
        "request method belongs to a different MCP lifecycle family",
        Some(serde_json::json!({"protocolVersion": expected})),
    )
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FamilyState {
    Unopened,
    Modern,
    Legacy,
}

#[cfg(test)]
mod tests {
    use rmcp::model::RequestId;

    use super::{AdmissionFailure, MAX_IN_FLIGHT_REQUESTS, RequestAdmission};

    #[test]
    fn response_lifetime_and_cancellation_release_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        let id = RequestId::Number(1);
        admission
            .reserve(id.clone())
            .map_err(|failure| format!("{failure:?}"))?;
        let request = admission.claim(id.clone())?;
        admission.start_response(&id);
        drop(request);
        admission.cancel(&id);
        assert_eq!(admission.active(), 1);
        admission.finish_response(&id);
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn legacy_capacity_rejection_consumes_the_request_id() -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        admission.enter_legacy();
        for number in 0..MAX_IN_FLIGHT_REQUESTS {
            admission
                .reserve(RequestId::Number(i64::try_from(number)?))
                .map_err(|failure| format!("{failure:?}"))?;
        }
        let rejected = RequestId::String("rejected-at-capacity".into());
        assert_eq!(admission.reserve(rejected.clone()), Err(AdmissionFailure::Capacity));
        admission.finish_response(&RequestId::Number(0));
        assert_eq!(admission.reserve(rejected), Err(AdmissionFailure::Duplicate));
        Ok(())
    }
}
