//! Installing a license file by hand (portal download / email) — never
//! touches the network. Every refusal must leave the existing cache file
//! exactly as it was.

use std::collections::HashMap;
use std::path::PathBuf;

use hymmalm::{LicenseClient, LicenseClientOptions, LicenseImportOutcome};
use serde_json::Value;

const PRODUCT: &str = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
const MACHINE: &str = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";

fn load_vectors() -> (HashMap<String, String>, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/vectors.json");
    let vec: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = vec["Cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["Name"].as_str().unwrap().to_string(),
                c["Jws"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let jwks = serde_json::to_string(&[&vec["RsaJwk"]]).unwrap();
    (cases, jwks)
}

struct Fixture {
    dir: PathBuf,
    cache: PathBuf,
    cases: HashMap<String, String>,
    jwks: String,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let (cases, jwks) = load_vectors();
        let dir = std::env::temp_dir().join(format!("hymmalm-import-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("cache.lic");
        std::fs::write(&cache, &cases["rs256-trial-valid"]).unwrap();
        Fixture { dir, cache, cases, jwks }
    }

    fn client(&self, product: &str, machine: &str) -> LicenseClient {
        LicenseClient::new(LicenseClientOptions {
            base_url: Some("http://127.0.0.1:1/api/".into()),
            product_id: product.into(),
            client_api_key: "PUB_test".into(),
            jwks_json: self.jwks.clone(),
            machine_id: Some(machine.into()),
            machine_name: Some("SHOP-FLOOR-01".into()),
            license_path: Some(self.cache.clone()),
            ..Default::default()
        })
        .unwrap()
    }

    fn cached(&self) -> String {
        std::fs::read_to_string(&self.cache).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn genuine_file_installs() {
    let f = Fixture::new("genuine");
    let src = f.dir.join("downloaded.lic");
    // a BOM and a trailing newline, as a browser download may add
    std::fs::write(&src, format!("\u{feff}{}\r\n", f.cases["rs256-paid-valid"])).unwrap();

    let mut c = f.client(PRODUCT, MACHINE);
    assert_eq!(c.license_path(), Some(f.cache.clone()));
    let r = c.import_license_file(&src).unwrap();
    assert!(r.succeeded(), "{r:?}");
    assert_eq!(r.message, "License file installed.");
    assert_eq!(r.installed_path, Some(f.cache.clone()));
    assert_eq!(c.license_id(), "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0");
    assert_eq!(f.cached(), f.cases["rs256-paid-valid"]);
}

#[test]
fn refusals_leave_the_cache_untouched() {
    let f = Fixture::new("refusals");
    let trial = f.cases["rs256-trial-valid"].clone();

    let r = f.client(PRODUCT, MACHINE).import_license(&f.cases["rs256-tampered-payload"]).unwrap();
    assert_eq!(r.outcome, LicenseImportOutcome::SignatureInvalid);
    assert!(r.message.contains("or it has been changed"), "{}", r.message);
    assert_eq!(f.cached(), trial);

    let r = f.client("PRD_OTHER", MACHINE).import_license(&f.cases["rs256-paid-valid"]).unwrap();
    assert_eq!(r.outcome, LicenseImportOutcome::WrongProduct);
    assert_eq!(r.message, "This license file is for CADshift Nesting, not this one.");
    assert_eq!(f.cached(), trial);

    let other = format!("OTHER{}", "0".repeat(47));
    let r = f.client(PRODUCT, &other).import_license(&f.cases["rs256-paid-valid"]).unwrap();
    assert_eq!(r.outcome, LicenseImportOutcome::WrongComputer);
    assert!(r.message.contains("for the computer SHOP-FLOOR-01"), "{}", r.message);
    assert_eq!(f.cached(), trial);

    let r = f.client(PRODUCT, MACHINE).import_license("not a license at all").unwrap();
    assert_eq!(r.outcome, LicenseImportOutcome::NotALicenseFile);
    assert!(!r.succeeded());
    assert_eq!(f.cached(), trial);

    let r = f.client(PRODUCT, MACHINE).import_license_file(&f.dir.join("missing.lic")).unwrap();
    assert_eq!(r.outcome, LicenseImportOutcome::NotALicenseFile);
    assert!(r.message.starts_with("The file could not be read"), "{}", r.message);
    assert_eq!(f.cached(), trial);
}
