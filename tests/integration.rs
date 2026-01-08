use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use chrono::Utc;
use nilauth_client::client::{
    BlindModule, DefaultNilauthClient, NilauthClient, RequestTokenError, RevokeTokenArgs, ValidatePaymentError,
};
use nillion_nucs::{NucSigner, Signer, did::Did, envelope::NucTokenEnvelope, signer::DidMethod};
use rstest::rstest;
use serial_test::serial;
use setup::{NilAuth, nilauth};
use std::str::FromStr;
use std::time::Duration;

mod setup;

/// Anvil test user account #1 private key (has NIL tokens minted by DeployLocal.s.sol)
const ANVIL_PRIVATE_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Contract addresses from DeployLocal.s.sol
const NIL_TOKEN_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const BURN_CONTRACT_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

/// Anvil default chain ID
const ANVIL_CHAIN_ID: u64 = 31337;

// Define the contract ABIs
sol! {
    #[sol(rpc)]
    contract IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    contract IBurnWithDigest {
        function burnWithDigest(uint256 amount, bytes32 digest) external;
    }
}

/// Helper to perform an on-chain burn transaction via Anvil.
///
/// Returns the transaction hash.
async fn burn_on_chain(rpc_url: &str, amount_wei: u128, digest: [u8; 32]) -> String {
    let signer: PrivateKeySigner = ANVIL_PRIVATE_KEY.parse().expect("invalid private key");
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url.parse().expect("invalid url"));

    let nil_token = Address::from_str(NIL_TOKEN_ADDRESS).expect("invalid address");
    let burn_contract = Address::from_str(BURN_CONTRACT_ADDRESS).expect("invalid address");

    // First approve the burn contract to spend tokens
    let token = IERC20::new(nil_token, &provider);
    let approve_tx = token.approve(burn_contract, U256::from(amount_wei)).send().await.expect("approve failed");
    let _ = approve_tx.get_receipt().await.expect("approve receipt failed");

    // Now perform the burn
    let burner = IBurnWithDigest::new(burn_contract, &provider);
    let digest_b256 = B256::from_slice(&digest);
    let burn_tx = burner.burnWithDigest(U256::from(amount_wei), digest_b256).send().await.expect("burn failed");

    let receipt = burn_tx.get_receipt().await.expect("burn receipt failed");
    format!("0x{}", hex::encode(receipt.transaction_hash.as_slice()))
}

/// Helper to pay for a subscription using the new ERC-20 flow.
async fn pay_subscription(
    client: &DefaultNilauthClient,
    rpc_url: &str,
    blind_module: BlindModule,
    payer_signer: &dyn NucSigner,
    subscriber_did: Did,
) -> Result<(), ValidatePaymentError> {
    // 1. Create payment resource
    let resource = client.create_payment_resource(blind_module, *payer_signer.did(), subscriber_did);

    // 2. Get the cost and perform on-chain payment
    let cost_unils = client.subscription_cost(blind_module).await.map_err(|e| {
        ValidatePaymentError::Request(nilauth_client::RequestError {
            message: e.to_string(),
            error_code: "COST_FETCH_FAILED".to_string(),
        })
    })?;

    // NIL token has 6 decimals, so 1 unil = 1 smallest token unit.
    // No conversion needed - pass the unil amount directly to the contract.
    let amount_token_units = cost_unils as u128;

    let tx_hash = burn_on_chain(rpc_url, amount_token_units, resource.digest).await;

    // 3. Validate the payment with nilauth
    client.validate_payment(&tx_hash, &resource.payload, payer_signer).await
}

#[rstest]
#[tokio::test]
#[serial]
async fn pay_and_mint(nilauth: NilAuth) {
    let rpc_url = &nilauth.config.payments.ethereum_rpc_url;
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let payer_signer = Signer::generate(DidMethod::Key);
    let subscriber_signer = Signer::generate(DidMethod::Key);
    let subscriber_did = *subscriber_signer.did();
    let blind_module = BlindModule::NilDb;

    // The Payer pays for the Subscriber's subscription
    pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // The Subscriber can now check their status
    let subscription =
        client.subscription_status(subscriber_did, blind_module).await.expect("failed to get subscription status");
    assert!(subscription.subscribed);
    subscription.details.expect("no subscription information");

    // The Subscriber can mint a token
    let token = client.request_token(&*subscriber_signer, blind_module).await.expect("failed to mint token");
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
#[serial]
async fn pay_all_modules(nilauth: NilAuth) {
    let rpc_url = &nilauth.config.payments.ethereum_rpc_url;
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let payer_signer = Signer::generate(DidMethod::Key);
    let subscriber_signer = Signer::generate(DidMethod::Key);
    let subscriber_did = *subscriber_signer.did();

    for blind_module in [BlindModule::NilDb, BlindModule::NilAi] {
        pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
            .await
            .expect("failed to pay subscription");
    }
}

#[rstest]
#[tokio::test]
async fn subscription_status_without_subscription(nilauth: NilAuth) {
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let signer = Signer::generate(DidMethod::Key);
    let subscription =
        client.subscription_status(*signer.did(), BlindModule::NilDb).await.expect("failed to get subscription status");
    assert!(!subscription.subscribed);
    assert!(subscription.details.is_none());
}

#[rstest]
#[tokio::test]
async fn mint_without_paying(nilauth: NilAuth) {
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let signer = Signer::generate(DidMethod::Key);
    let err = client.request_token(&*signer, BlindModule::NilDb).await.expect_err("token minted successfully");
    let RequestTokenError::Request(err) = err else { panic!("not a request error: {err}") };
    assert_eq!(err.error_code, "NOT_SUBSCRIBED");
}

#[rstest]
#[tokio::test]
#[serial]
async fn pay_too_soon(nilauth: NilAuth) {
    let rpc_url = &nilauth.config.payments.ethereum_rpc_url;
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let payer_signer = Signer::generate(DidMethod::Key);
    let subscriber_signer = Signer::generate(DidMethod::Key);
    let subscriber_did = *subscriber_signer.did();
    let blind_module = BlindModule::NilDb;

    pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // Pay again, this should fail because we just started our subscription
    let err = pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
        .await
        .expect_err("subscription payment succeeded");
    let ValidatePaymentError::Request(err) = err else { panic!("not a request error: {err}") };
    assert_eq!(err.error_code, "CANNOT_RENEW_YET");
}

#[rstest]
#[tokio::test]
#[serial]
async fn list_unrevoked(nilauth: NilAuth) {
    let rpc_url = &nilauth.config.payments.ethereum_rpc_url;
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let payer_signer = Signer::generate(DidMethod::Key);
    let subscriber_signer = Signer::generate(DidMethod::Key);
    let subscriber_did = *subscriber_signer.did();
    let blind_module = BlindModule::NilDb;

    pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
        .await
        .expect("failed to pay subscription");

    let token = client.request_token(&*subscriber_signer, blind_module).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");
    let revocations = client.lookup_revoked_tokens(&token).await.expect("look up failed");
    assert_eq!(revocations.len(), 0);
}

#[rstest]
#[tokio::test]
#[serial]
async fn revoke(nilauth: NilAuth) {
    let rpc_url = &nilauth.config.payments.ethereum_rpc_url;
    let client = DefaultNilauthClient::create(&nilauth.endpoint, ANVIL_CHAIN_ID).await.expect("failed to build client");
    let payer_signer = Signer::generate(DidMethod::Key);
    let subscriber_signer = Signer::generate(DidMethod::Key);
    let subscriber_did = *subscriber_signer.did();
    let blind_module = BlindModule::NilDb;

    pay_subscription(&client, rpc_url, blind_module, &*payer_signer, subscriber_did)
        .await
        .expect("failed to pay subscription");

    // The subscriber gets a token, creates a new one and revokes it
    let token = client.request_token(&*subscriber_signer, blind_module).await.expect("failed to mint");
    let token = NucTokenEnvelope::decode(&token).expect("invalid token");

    client
        .revoke_token(
            RevokeTokenArgs { auth_token: token.clone(), revocable_token: token.clone() },
            &*subscriber_signer,
        )
        .await
        .expect("failed to revoke");

    let revocations = client.lookup_revoked_tokens(&token).await.expect("look up failed");
    let hashes: Vec<_> = revocations.into_iter().map(|r| r.token_hash).collect();
    assert_eq!(hashes, &[token.token().compute_hash()]);
}
