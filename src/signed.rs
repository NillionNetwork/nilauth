use nillion_nucs::k256::ecdsa::signature::Verifier;
use nillion_nucs::k256::ecdsa::{Signature, VerifyingKey};
use nillion_nucs::k256::PublicKey;
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub(crate) struct SignedRequest {
    //// The public key for the keypair that signed this request, in hex form.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::public_key))]
    pub(crate) public_key: [u8; 33],

    //// The request signature, in hex form.
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::signature))]
    pub(crate) signature: [u8; 64],

    /// The payload
    #[serde(with = "hex::serde")]
    #[schema(value_type = String, examples(crate::docs::hex_payload))]
    pub(crate) payload: Vec<u8>,
}

impl SignedRequest {
    #[cfg(test)]
    pub(crate) fn new<T>(key: &nillion_nucs::k256::SecretKey, payload: &T) -> Self
    where
        T: serde::Serialize,
    {
        use nillion_nucs::k256::ecdsa::{signature::Signer, SigningKey};

        let payload = serde_json::to_string(&payload).expect("failed to serialize payload");
        let signature: Signature = SigningKey::from(key.clone()).sign(payload.as_bytes());
        let signature = signature.to_bytes().try_into().unwrap();
        let public_key_bytes: [u8; 33] = key.public_key().to_sec1_bytes().as_ref().try_into().unwrap();
        SignedRequest { public_key: public_key_bytes, signature, payload: payload.as_bytes().to_vec() }
    }

    pub(crate) fn verify(self) -> Result<PublicKey, VerificationError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use nillion_nucs::k256::{
        ecdsa::{signature::SignerMut, SigningKey},
        SecretKey,
    };

    #[test]
    fn valid_signature() {
        let key = SecretKey::random(&mut rand::thread_rng());
        let payload = rand::random::<[u8; 16]>().to_vec();
        let signature: Signature = SigningKey::from(&key).sign(&payload);
        let request = SignedRequest {
            public_key: key.public_key().to_sec1_bytes().as_ref().try_into().unwrap(),
            signature: signature.to_bytes().into(),
            payload,
        };
        let public_key = request.verify().expect("verification failed");
        assert_eq!(public_key, key.public_key());
    }

    #[test]
    fn invalid_signature() {
        let signing_key = SecretKey::random(&mut rand::thread_rng());
        let other_key = SecretKey::random(&mut rand::thread_rng());
        let payload = rand::random::<[u8; 16]>().to_vec();
        let signature: Signature = SigningKey::from(&signing_key).sign(&payload);
        let request = SignedRequest {
            public_key: other_key.public_key().to_sec1_bytes().as_ref().try_into().unwrap(),
            signature: signature.to_bytes().into(),
            payload,
        };
        request.verify().expect_err("verification succeeded");
    }
}
