use crate::state::SharedState;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct About {
    #[serde(serialize_with = "hex::serde::serialize")]
    public_key: Box<[u8]>,

    build: BuildInfo,

    started: DateTime<Utc>,
}

#[derive(Serialize)]
struct BuildInfo {
    commit: String,
    timestamp: DateTime<Utc>,
}

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
