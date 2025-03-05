use crate::state::SharedState;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct About {
    #[serde(serialize_with = "hex::serde::serialize")]
    public_key: Box<[u8]>,
}

pub(crate) async fn handler(state: SharedState) -> Json<About> {
    About {
        public_key: state.0.secret_key.public_key().to_sec1_bytes(),
    }
    .into()
}
