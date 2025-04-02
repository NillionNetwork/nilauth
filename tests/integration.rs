use chrono::Utc;
use nilauth_client::client::{
    DefaultNilauthClient, NilauthClient, PaySubscriptionError, RequestTokenError,
};
use nillion_nucs::{envelope::NucTokenEnvelope, k256::SecretKey, token::Did};
use rstest::rstest;
use setup::{nilauth, NilAuth};
use std::time::Duration;

mod setup;

#[rstest]
#[tokio::test]
async fn pay_and_mint(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");
    let subscription = client
        .subscription_status(&key)
        .await
        .expect("failed to get subscription status");
    assert!(subscription.subscribed);
    subscription.details.expect("no subscription information");
    let token = client
        .request_token(&key)
        .await
        .expect("failed to mint token");
    let token = NucTokenEnvelope::decode(&token)
        .expect("invalid token returned")
        .validate_signatures()
        .expect("invalid signature")
        .into_parts()
        .0
        .into_token();
    assert_eq!(
        token.audience,
        Did::new(
            key.public_key()
                .to_sec1_bytes()
                .as_ref()
                .try_into()
                .unwrap()
        )
    );

    // Calculate what the expiration time could be and give it a bit of a buffer
    let minimum_expiration_time =
        Utc::now() + nilauth.config.payments.subscriptions.length - Duration::from_secs(10);
    assert!(token.expires_at.expect("no expiration on token") > minimum_expiration_time);
}

#[rstest]
#[tokio::test]
async fn subscription_status_without_subscription(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    let subscription = client
        .subscription_status(&key)
        .await
        .expect("failed to get subscription status");
    assert!(!subscription.subscribed);
    assert!(subscription.details.is_none());
}

#[rstest]
#[tokio::test]
async fn mint_without_paying(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    let err = client
        .request_token(&key)
        .await
        .expect_err("token minted successfully");
    let RequestTokenError::Request(err) = err else {
        panic!("not a request error: {err}")
    };
    assert_eq!(err.error_code, "NOT_SUBSCRIBED");
}

#[rstest]
#[tokio::test]
async fn pay_too_soon(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");

    // Pay again, this should fail because we just started our subscription
    let err = client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect_err("subscription payment succeeded");
    let PaySubscriptionError::Request(err) = err else {
        panic!("not a request error: {err}")
    };
    assert_eq!(err.error_code, "CANNOT_RENEW_YET");
}

#[rstest]
#[tokio::test]
async fn list_unrevoked(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");
    let token = client.request_token(&key).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");
    let revocations = client
        .lookup_revoked_tokens(&token)
        .await
        .expect("look up failed");
    assert_eq!(revocations.len(), 0);
}

#[rstest]
#[tokio::test]
async fn revoke(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let key = SecretKey::random(&mut rand::thread_rng());
    client
        .pay_subscription(
            &mut *nilauth.nilchain_client.lock().await,
            &key.public_key(),
        )
        .await
        .expect("failed to pay subscription");

    // Get a token, create a new one and revoke it
    let token = client.request_token(&key).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");

    client
        .revoke_token(&token, &key)
        .await
        .expect("failed to revoke");

    let revocations = client
        .lookup_revoked_tokens(&token)
        .await
        .expect("look up failed");
    let hashes: Vec<_> = revocations.into_iter().map(|r| r.token_hash).collect();
    assert_eq!(hashes, &[token.token().compute_hash()]);
}
