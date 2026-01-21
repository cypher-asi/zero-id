//! Namespace management API handlers.
//!
//! Provides endpoints for namespace CRUD operations and membership management.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::{IdentityCore, NamespaceRole};

use crate::{
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

use super::helpers::format_timestamp_rfc3339;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateNamespaceRequest {
    pub namespace_id: Option<Uuid>,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct NamespaceResponse {
    pub namespace_id: Uuid,
    pub name: String,
    pub owner_identity_id: Uuid,
    pub active: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListNamespacesResponse {
    pub namespaces: Vec<NamespaceResponse>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNamespaceRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub identity_id: Uuid,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub identity_id: Uuid,
    pub namespace_id: Uuid,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_role(role_str: &str) -> Result<NamespaceRole, ApiError> {
    match role_str.to_lowercase().as_str() {
        "owner" => Ok(NamespaceRole::Owner),
        "admin" => Ok(NamespaceRole::Admin),
        "member" => Ok(NamespaceRole::Member),
        _ => Err(ApiError::InvalidRequest(format!(
            "Invalid role: {}. Must be one of: owner, admin, member",
            role_str
        ))),
    }
}

fn role_to_string(role: NamespaceRole) -> String {
    match role {
        NamespaceRole::Owner => "owner".to_string(),
        NamespaceRole::Admin => "admin".to_string(),
        NamespaceRole::Member => "member".to_string(),
    }
}

// ============================================================================
// Namespace CRUD Handlers
// ============================================================================

/// POST /v1/namespaces - Create a new namespace
pub async fn create_namespace(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<NamespaceResponse>), ApiError> {
    let owner_identity_id = auth.claims.identity_id()?;
    let namespace_id = req.namespace_id.unwrap_or_else(Uuid::new_v4);

    let namespace = state
        .identity_service
        .create_namespace(namespace_id, req.name, owner_identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let created_at = format_timestamp_rfc3339(namespace.created_at)?;

    Ok((
        StatusCode::CREATED,
        Json(NamespaceResponse {
            namespace_id: namespace.namespace_id,
            name: namespace.name,
            owner_identity_id: namespace.owner_identity_id,
            active: namespace.active,
            created_at,
        }),
    ))
}

/// GET /v1/namespaces - List namespaces for authenticated identity
pub async fn list_namespaces(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Result<Json<ListNamespacesResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    let namespaces = state
        .identity_service
        .list_namespaces(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let namespace_responses: Result<Vec<_>, ApiError> = namespaces
        .into_iter()
        .map(|ns| {
            Ok(NamespaceResponse {
                namespace_id: ns.namespace_id,
                name: ns.name,
                owner_identity_id: ns.owner_identity_id,
                active: ns.active,
                created_at: format_timestamp_rfc3339(ns.created_at)?,
            })
        })
        .collect();

    Ok(Json(ListNamespacesResponse {
        namespaces: namespace_responses?,
    }))
}

/// GET /v1/namespaces/:namespace_id - Get namespace details
pub async fn get_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
) -> Result<Json<NamespaceResponse>, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    // Verify requester is a member
    let membership = state
        .identity_service
        .get_namespace_membership(requester_id, namespace_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    if membership.is_none() {
        return Err(ApiError::Forbidden(
            "Not a member of this namespace".to_string(),
        ));
    }

    let namespace = state
        .identity_service
        .get_namespace(namespace_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let created_at = format_timestamp_rfc3339(namespace.created_at)?;

    Ok(Json(NamespaceResponse {
        namespace_id: namespace.namespace_id,
        name: namespace.name,
        owner_identity_id: namespace.owner_identity_id,
        active: namespace.active,
        created_at,
    }))
}

/// PATCH /v1/namespaces/:namespace_id - Update namespace
pub async fn update_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
    Json(req): Json<UpdateNamespaceRequest>,
) -> Result<Json<NamespaceResponse>, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    let namespace = state
        .identity_service
        .update_namespace(namespace_id, req.name, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let created_at = format_timestamp_rfc3339(namespace.created_at)?;

    Ok(Json(NamespaceResponse {
        namespace_id: namespace.namespace_id,
        name: namespace.name,
        owner_identity_id: namespace.owner_identity_id,
        active: namespace.active,
        created_at,
    }))
}

/// POST /v1/namespaces/:namespace_id/deactivate - Deactivate namespace
pub async fn deactivate_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    state
        .identity_service
        .deactivate_namespace(namespace_id, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/namespaces/:namespace_id/reactivate - Reactivate namespace
pub async fn reactivate_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    state
        .identity_service
        .reactivate_namespace(namespace_id, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /v1/namespaces/:namespace_id - Delete namespace
pub async fn delete_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    state
        .identity_service
        .delete_namespace(namespace_id, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Membership Management Handlers
// ============================================================================

/// GET /v1/namespaces/:namespace_id/members - List namespace members
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
) -> Result<Json<ListMembersResponse>, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    let members = state
        .identity_service
        .list_namespace_members(namespace_id, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let member_responses: Result<Vec<_>, ApiError> = members
        .into_iter()
        .map(|m| {
            Ok(MemberResponse {
                identity_id: m.identity_id,
                namespace_id: m.namespace_id,
                role: role_to_string(m.role),
                joined_at: format_timestamp_rfc3339(m.joined_at)?,
            })
        })
        .collect();

    Ok(Json(ListMembersResponse {
        members: member_responses?,
    }))
}

/// POST /v1/namespaces/:namespace_id/members - Add member to namespace
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(namespace_id): Path<Uuid>,
    auth: AuthenticatedUser,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<MemberResponse>), ApiError> {
    let requester_id = auth.claims.identity_id()?;
    let role = parse_role(&req.role)?;

    let membership = state
        .identity_service
        .add_namespace_member(namespace_id, req.identity_id, role, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let joined_at = format_timestamp_rfc3339(membership.joined_at)?;

    Ok((
        StatusCode::CREATED,
        Json(MemberResponse {
            identity_id: membership.identity_id,
            namespace_id: membership.namespace_id,
            role: role_to_string(membership.role),
            joined_at,
        }),
    ))
}

/// Path parameters for member operations
#[derive(Debug, Deserialize)]
pub struct MemberPathParams {
    pub namespace_id: Uuid,
    pub identity_id: Uuid,
}

/// PATCH /v1/namespaces/:namespace_id/members/:identity_id - Update member role
pub async fn update_member(
    State(state): State<Arc<AppState>>,
    Path(params): Path<MemberPathParams>,
    auth: AuthenticatedUser,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, ApiError> {
    let requester_id = auth.claims.identity_id()?;
    let role = parse_role(&req.role)?;

    let membership = state
        .identity_service
        .update_namespace_member(params.namespace_id, params.identity_id, role, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let joined_at = format_timestamp_rfc3339(membership.joined_at)?;

    Ok(Json(MemberResponse {
        identity_id: membership.identity_id,
        namespace_id: membership.namespace_id,
        role: role_to_string(membership.role),
        joined_at,
    }))
}

/// DELETE /v1/namespaces/:namespace_id/members/:identity_id - Remove member
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path(params): Path<MemberPathParams>,
    auth: AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    let requester_id = auth.claims.identity_id()?;

    state
        .identity_service
        .remove_namespace_member(params.namespace_id, params.identity_id, requester_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}
