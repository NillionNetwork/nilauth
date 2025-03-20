use nilauth_client::client::{DefaultNilauthClient, NilauthClient};
use nillion_nucs::{envelope::NucTokenEnvelope, k256::SecretKey, token::Did};
use rstest::rstest;
use setup::{nilauth, NilAuth};

mod setup;

#[rstest]
#[tokio::test]
async fn payment(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint);
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");
    let token = client
        .request_token(&key)
        .await
        .expect("failed to mint token");
    let token = NucTokenEnvelope::decode(&token)
        .expect("invalid token returned")
        .validate_signatures()
        .expect("invalid signature");
    assert_eq!(
        token.token().token().audience,
        Did::new(
            key.public_key()
                .to_sec1_bytes()
                .as_ref()
                .try_into()
                .unwrap()
        )
    );
}

#[rstest]
#[tokio::test]
async fn pay_too_soon(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint);
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");
    // Pay again, this should fail because we just started our subscription
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect_err("subscription payment succeeded");
}
