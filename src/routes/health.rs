use axum::response::{IntoResponse, Response};
use reqwest::StatusCode;

/// Check the health of this service.
#[utoipa::path(
    get,
    path = "/health",
    responses((status = OK, body = String, description = "A string `OK` if the service is up and running", example = "OK"))
)]
pub(crate) async fn handler() -> Response {
    (StatusCode::OK, "OK").into_response()
}
