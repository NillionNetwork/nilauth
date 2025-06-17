use crate::state::SharedState;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub(crate) struct About {
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::public_key))]
    public_key: Box<[u8]>,

    build: BuildInfo,

    started: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct BuildInfo {
    #[schema(examples("ff0d9198d1b8819527bc036a58f875c4046b6f21"))]
    commit: String,
    timestamp: DateTime<Utc>,
}

/// Get general information about this nilauth instance.
#[utoipa::path(get, path = "/about", responses((status = OK, body = About, description = "Information about this nilauth instance")))]
pub(crate) async fn handler(state: SharedState) -> Json<About> {
    let build_timestamp = env!("BUILD_TIMESTAMP").parse().unwrap_or(0);
    let build_timestamp = DateTime::from_timestamp(build_timestamp, 0).unwrap_or_default();
    About {
        started: state.parameters.started_at,
        public_key: state.parameters.secret_key.public_key().to_sec1_bytes(),
        build: BuildInfo {
            commit: env!("BUILD_GIT_COMMIT_HASH").to_string(),
            timestamp: build_timestamp,
        },
    }
    .into()
}
