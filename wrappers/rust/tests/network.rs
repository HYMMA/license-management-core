//! A transport failure says WHAT failed and names the host to allow,
//! instead of a bare "network failure". Uses causes this machine produces
//! on its own: nothing listens on 127.0.0.1:1.

use hymmalm::{LicenseClient, LicenseClientOptions, NetworkFailure};

#[test]
fn refused_connection_is_classified_and_explained() {
    let jwks = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    let mut c = LicenseClient::new(LicenseClientOptions {
        base_url: Some("http://127.0.0.1:1/api/".into()),
        product_id: "PRD_01KWWPEPM0N070BDAHJ7G09RGV".into(),
        client_api_key: "PUB_test".into(),
        jwks_json: jwks.into(),
        machine_id: Some("KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG".into()),
        machine_name: Some("SHOP-FLOOR-01".into()),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(c.last_network_failure(), NetworkFailure::None);
    let err = c.check().expect_err("nothing listens on 127.0.0.1:1");
    assert_eq!(err.code, -7, "{err}");
    assert_eq!(c.last_network_failure(), NetworkFailure::Connection);
    assert!(
        err.detail.starts_with("Could not connect to 127.0.0.1."),
        "detail: {}",
        err.detail
    );
}
