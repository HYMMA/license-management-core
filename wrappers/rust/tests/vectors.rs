//! Vector-driven compatibility tests: the wrapper must verify exactly what
//! the license server signs (tests/vectors/*.json) and reject tampered
//! tokens, matching the C test suite case for case.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hymmalm::{LicenseError, LicenseStatus};
use serde_json::Value;

const VECTOR_FILES: &[&str] = &["vectors.json", "vectors-eddsa.json"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(name: &str) -> Value {
    let path = repo_root().join("tests/vectors").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

/// JWKS = JSON array of whichever of RsaJwk/EcJwk/EdJwk the file has.
fn jwks_of(vec: &Value) -> String {
    let keys: Vec<&Value> = ["RsaJwk", "EcJwk", "EdJwk"]
        .iter()
        .filter_map(|k| vec.get(*k))
        .collect();
    serde_json::to_string(&keys).unwrap()
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date
/// (Howard Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse exactly the shape the vectors use: "YYYY-MM-DDThh:mm:ssZ".
fn parse_iso_z(s: &str) -> i64 {
    assert!(
        s.len() == 20 && s.ends_with('Z'),
        "unexpected NowUtc shape: {s}"
    );
    let n = |a: usize, l: usize| s[a..a + l].parse::<i64>().unwrap();
    days_from_civil(n(0, 4), n(5, 2), n(8, 2)) * 86400 + n(11, 2) * 3600 + n(14, 2) * 60 + n(17, 2)
}

fn parse_now(case: &Value) -> Option<SystemTime> {
    let s = case.get("NowUtc")?.as_str()?;
    Some(UNIX_EPOCH + Duration::from_secs(parse_iso_z(s) as u64))
}

fn status_by_name(name: &str) -> LicenseStatus {
    match name {
        "Unknown" => LicenseStatus::Unknown,
        "Expired" => LicenseStatus::Expired,
        "Valid" => LicenseStatus::Valid,
        "ValidTrial" => LicenseStatus::ValidTrial,
        "InvalidTrial" => LicenseStatus::InvalidTrial,
        "ReceiptExpired" => LicenseStatus::ReceiptExpired,
        "ReceiptUnregistered" => LicenseStatus::ReceiptUnregistered,
        other => panic!("unknown ExpectedStatus {other}"),
    }
}

#[test]
fn all_vector_cases() {
    for fname in VECTOR_FILES {
        let vec = load(fname);
        let jwks = jwks_of(&vec);
        for case in vec["Cases"].as_array().expect("Cases array") {
            let name = case["Name"].as_str().unwrap();
            let jws = case["Jws"].as_str().unwrap();
            let now = parse_now(case);
            let ctx = format!("{fname}/{name}");
            if case.get("Valid").and_then(Value::as_bool).unwrap_or(false) {
                let status =
                    hymmalm::verify(jws, &jwks, None, None, now).unwrap_or_else(|e| {
                        panic!("{ctx}: expected Ok, got {e} (code {})", e.code)
                    });
                if let Some(expected) = case.get("ExpectedStatus").and_then(Value::as_str) {
                    assert_eq!(status, status_by_name(expected), "{ctx}");
                }
            } else {
                let err: LicenseError = hymmalm::verify(jws, &jwks, None, None, now)
                    .expect_err(&format!("{ctx}: expected rejection"));
                assert!(
                    err.code == -4 || err.code == -3,
                    "{ctx}: expected signature-invalid (-4) or malformed (-3), got {}",
                    err.code
                );
            }
        }
    }
}

#[test]
fn product_and_machine_binding() {
    let vec = load("vectors.json");
    let jwks = jwks_of(&vec);
    let case = vec["Cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["Name"] == "rs256-trial-valid")
        .expect("rs256-trial-valid case");
    let jws = case["Jws"].as_str().unwrap();
    let now = parse_now(case);
    let product = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
    let mac = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";

    assert_eq!(
        hymmalm::verify(jws, &jwks, Some(product), Some(mac), now).unwrap(),
        LicenseStatus::ValidTrial
    );

    let err = hymmalm::verify(jws, &jwks, Some("PRD_SOMETHINGELSE"), Some(mac), now)
        .expect_err("product mismatch must fail");
    assert_eq!(err.code, -10, "product mismatch");

    let err = hymmalm::verify(jws, &jwks, Some(product), Some("WRONGMACHINE"), now)
        .expect_err("computer mismatch must fail");
    assert_eq!(err.code, -11, "computer mismatch");
}

#[test]
fn machine_identity() {
    assert_eq!(hymmalm::machine_id().unwrap().len(), 52);
    assert!(!hymmalm::machine_name().unwrap().is_empty());
}

#[test]
fn error_names() {
    let err = LicenseError {
        code: -4,
        detail: String::new(),
    };
    assert!(err.to_string().contains("signature"), "got: {err}");
}
