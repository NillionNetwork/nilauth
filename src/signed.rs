use nillion_nucs::k256::PublicKey;
use nillion_nucs::k256::ecdsa::signature::Verifier;
use nillion_nucs::k256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub(crate) struct SignedRequest {
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::public_key))]
    pub(crate) public_key: [u8; 33],

    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::signature))]
    pub(crate) signature: [u8; 64],

    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::hex_payload))]
    pub(crate) payload: Vec<u8>,
}

impl SignedRequest {
    pub(crate) fn verify(&self) -> Result<PublicKey, VerificationError> {
        use VerificationError::*;
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.public_key).map_err(|_| InvalidPublicKey)?;
        let signature = Signature::from_bytes(&self.signature.into()).map_err(|_| InvalidSignature)?;
        verifying_key.verify(&self.payload, &signature).map_err(|_| SignatureVerification)?;
        Ok(PublicKey::from(verifying_key))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum VerificationError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerification,
}
