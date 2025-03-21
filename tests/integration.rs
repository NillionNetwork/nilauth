use rstest::rstest;
use setup::{nilauth, NilAuth};
mod setup;

#[rstest]
#[tokio::test]
async fn potato(nilauth: NilAuth) {
    println!("nilauth is up at {}", nilauth.endpoint);
}
