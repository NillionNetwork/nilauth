use chrono::Utc;
use nilauth_client::client::{
    BlindModule, DefaultNilauthClient, NilauthClient, PaySubscriptionError, RequestTokenError, RevokeTokenArgs,
};
use nillion_nucs::{DidMethod, Keypair, envelope::NucTokenEnvelope};
use rstest::rstest;
use setup::{NilAuth, nilauth};
use std::time::Duration;

mod setup;

#[rstest]
#[tokio::test]
async fn pay_and_mint(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let payer_keypair = Keypair::generate();
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
    let blind_module = BlindModule::NilDb;

    // The Payer pays for the Subscriber's subscription
    client
        .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // The Subscriber can now check their status
    let subscription =
        client.subscription_status(subscriber_did, blind_module).await.expect("failed to get subscription status");
    assert!(subscription.subscribed);
    subscription.details.expect("no subscription information");

    // The Subscriber can mint a token
    let token = client.request_token(&subscriber_keypair, blind_module).await.expect("failed to mint token");
    let token = NucTokenEnvelope::decode(&token)
        .expect("invalid token returned")
        .validate_signatures()
        .expect("invalid signature")
        .into_parts()
        .0
        .into_token();
    assert_eq!(token.audience, subscriber_did);
    assert_eq!(token.command, ["nil", "db"].into());

    // Calculate what the expiration time could be and give it a bit of a buffer
    let minimum_expiration_time = Utc::now() + nilauth.config.payments.subscriptions.length - Duration::from_secs(10);
    assert!(token.expires_at.expect("no expiration on token") > minimum_expiration_time);
}

#[rstest]
#[tokio::test]
async fn pay_all_modules(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let payer_keypair = Keypair::generate();
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);

    for blind_module in [BlindModule::NilDb, BlindModule::NilAi] {
        client
            .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
            .await
            .expect("failed to pay subscription");
    }
}

#[rstest]
#[tokio::test]
async fn subscription_status_without_subscription(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let keypair = Keypair::generate();
    let subscription = client
        .subscription_status(keypair.to_did(DidMethod::Key), BlindModule::NilDb)
        .await
        .expect("failed to get subscription status");
    assert!(!subscription.subscribed);
    assert!(subscription.details.is_none());
}

#[rstest]
#[tokio::test]
async fn mint_without_paying(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let keypair = Keypair::generate();
    let err = client.request_token(&keypair, BlindModule::NilDb).await.expect_err("token minted successfully");
    let RequestTokenError::Request(err) = err else { panic!("not a request error: {err}") };
    assert_eq!(err.error_code, "NOT_SUBSCRIBED");
}

#[rstest]
#[tokio::test]
async fn pay_too_soon(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let payer_keypair = Keypair::generate();
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
    let blind_module = BlindModule::NilDb;

    client
        .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // Pay again, this should fail because we just started our subscription
    let err = client
        .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
        .await
        .expect_err("subscription payment succeeded");
    let PaySubscriptionError::CannotRenewYet(_) = err else { panic!("not a request error: {err}") };
}

#[rstest]
#[tokio::test]
async fn list_unrevoked(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let payer_keypair = Keypair::generate();
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
    let blind_module = BlindModule::NilDb;

    client
        .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
        .await
        .expect("failed to pay subscription");

    let token = client.request_token(&subscriber_keypair, blind_module).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");
    let revocations = client.lookup_revoked_tokens(&token).await.expect("look up failed");
    assert_eq!(revocations.len(), 0);
}

#[rstest]
#[tokio::test]
async fn revoke(nilauth: NilAuth) {
    let client = DefaultNilauthClient::new(nilauth.endpoint).expect("failed to build client");
    let payer_keypair = Keypair::generate();
    let subscriber_keypair = Keypair::generate();
    let subscriber_did = subscriber_keypair.to_did(DidMethod::Key);
    let blind_module = BlindModule::NilDb;

    client
        .pay_subscription(&mut *nilauth.nilchain_client.lock().await, blind_module, &payer_keypair, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // The subscriber gets a token, creates a new one and revokes it
    let token = client.request_token(&subscriber_keypair, blind_module).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");

    client
        .revoke_token(
            RevokeTokenArgs { auth_token: token.clone(), revocable_token: token.clone() },
            &subscriber_keypair,
        )
        .await
        .expect("failed to revoke");

    let revocations = client.lookup_revoked_tokens(&token).await.expect("look up failed");
    let hashes: Vec<_> = revocations.into_iter().map(|r| r.token_hash).collect();
    assert_eq!(hashes, &[token.token().compute_hash()]);
}
