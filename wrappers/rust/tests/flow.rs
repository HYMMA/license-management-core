//! End-to-end client flow against a local mock of the license API.
//!
//! The mock serves the checked-in signed vectors and a fixed `GET DateTime`
//! (2026-07-10T00:00:00Z). HLM_TIMESYNC=off makes the native client resolve
//! its trusted evaluation time from that endpoint, so the expected statuses
//! are deterministic regardless of the real clock.
//!
//! The whole flow lives in ONE #[test]: the steps share the mock server's
//! mutable state, the HLM_TIMESYNC process env var, and a license cache
//! file, so they must run sequentially.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use hymmalm::{LicenseClient, LicenseClientOptions, LicenseStatus, SignedFormat};
use serde_json::Value;

const PRODUCT: &str = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
const MACHINE: &str = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";

// ---------------------------------------------------------------------------
// minimal hand-rolled HTTP/1.1 mock server
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// Which vector case GET /api/license serves.
    license_case: String,
    /// When set, every GET/POST answers with this status + fail_body.
    fail_status: Option<u16>,
    fail_body: String,
}

struct MockServer {
    base_url: String,
    state: Arc<Mutex<MockState>>,
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        401 => "Unauthorized",
        402 => "Payment Required",
        404 => "Not Found",
        _ => "Status",
    }
}

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let msg = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason(code),
        body.len(),
        body
    );
    let _ = stream.write_all(msg.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Read the request line + headers + Content-Length body.
/// Returns (method, path, body).
fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let content_length = lines
        .filter_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .next()
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((method, path, body))
}

/// Mirror the Python mock's PATCH rule: `"Code": <non-null>` switches to the
/// paid license; `"Code": null` switches to receipt-unregistered.
fn code_is_null(body: &str) -> bool {
    let Some(pos) = body.find("\"Code\"") else {
        return true;
    };
    let rest = &body[pos + "\"Code\"".len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':').unwrap_or(rest).trim_start();
    rest.starts_with("null")
}

fn handle(stream: &mut TcpStream, state: &Arc<Mutex<MockState>>, cases: &HashMap<String, String>) {
    let Some((method, path, body)) = read_request(stream) else {
        return;
    };
    let body = String::from_utf8_lossy(&body).into_owned();

    if method == "GET" || method == "POST" {
        let st = state.lock().unwrap();
        if let Some(code) = st.fail_status {
            let fail_body = if st.fail_body.is_empty() {
                "{}".to_string()
            } else {
                st.fail_body.clone()
            };
            drop(st);
            respond(stream, code, &fail_body);
            return;
        }
    }

    match method.as_str() {
        "GET" if path.starts_with("/api/DateTime") => {
            respond(stream, 200, "\"2026-07-10T00:00:00Z\"");
        }
        "GET" if path.starts_with("/api/computer") => {
            respond(stream, 200, "{\"id\":\"PC_01KWVTRYM7AXBT1V56M2N3E3AB\"}");
        }
        "GET" if path.starts_with("/api/license") => {
            let case = state.lock().unwrap().license_case.clone();
            respond(stream, 200, &cases[&case]);
        }
        "POST" => respond(stream, 201, "{}"),
        "PATCH" if path.starts_with("/api/license") => {
            state.lock().unwrap().license_case = if code_is_null(&body) {
                "rs256-receipt-unregistered".to_string()
            } else {
                "rs256-paid-valid".to_string()
            };
            respond(stream, 204, "");
        }
        _ => respond(stream, 404, "{}"),
    }
}

fn start_mock(cases: HashMap<String, String>) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(MockState {
        license_case: "rs256-trial-valid".to_string(),
        ..Default::default()
    }));

    let thread_state = Arc::clone(&state);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            handle(&mut stream, &thread_state, &cases);
        }
    });

    MockServer {
        base_url: format!("http://127.0.0.1:{port}/api/"),
        state,
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

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

fn client(
    jwks: &str,
    base: &str,
    path: Option<PathBuf>,
) -> hymmalm::Result<LicenseClient> {
    LicenseClient::new(LicenseClientOptions {
        base_url: Some(base.to_string()),
        product_id: PRODUCT.to_string(),
        client_api_key: "PUB_test".to_string(),
        jwks_json: jwks.to_string(),
        format: SignedFormat::Rs256,
        machine_id: Some(MACHINE.to_string()),
        machine_name: Some("SHOP-FLOOR-01".to_string()),
        license_path: path,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// the flow — one sequential test
// ---------------------------------------------------------------------------

#[test]
fn full_client_flow() {
    // The native core getenv()s this per call: resolve trusted time from the
    // mock's GET /api/DateTime instead of syncing against public sources.
    // Safe on edition 2021; the whole flow runs in this one test.
    std::env::set_var("HLM_TIMESYNC", "off");

    let (cases, jwks) = load_vectors();
    let mock = start_mock(cases);
    let dead_base = "http://127.0.0.1:1/api/";

    let lic_path = std::env::temp_dir().join(format!("hymmalm-flow-{}.lic", std::process::id()));
    let _ = std::fs::remove_file(&lic_path);

    // -- trial bootstrap → activate → offline cache → deactivate ----------
    {
        let mut c = client(&jwks, &mock.base_url, Some(lic_path.clone())).unwrap();
        assert_eq!(c.check().unwrap(), LicenseStatus::ValidTrial);
        assert_eq!(c.license_id(), "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0");
        assert_eq!(c.product_name(), "CADshift Nesting");
        assert!(c.trial_end().is_some());

        assert_eq!(
            c.activate("RCPT-CODE-1234").unwrap(),
            LicenseStatus::Valid
        );
        assert_eq!(c.buyer_email(), "jane@example.com");
        assert_eq!(c.metadata("seat"), "floor-1");
        assert!(c.live_mode());
        assert!(c.expires().is_some());
    }

    // A fresh client on a dead URL must surface the cached license.
    // (The native client retries transport failures 3x with backoff, so
    // this takes a couple of seconds.)
    {
        let mut c = client(&jwks, dead_base, Some(lic_path.clone())).unwrap();
        assert_eq!(c.check().unwrap(), LicenseStatus::Valid, "offline cache");
    }

    {
        let mut c = client(&jwks, &mock.base_url, Some(lic_path.clone())).unwrap();
        assert_eq!(c.check().unwrap(), LicenseStatus::Valid);
        assert_eq!(
            c.deactivate().unwrap(),
            LicenseStatus::ReceiptUnregistered
        );
    }
    let _ = std::fs::remove_file(&lic_path);

    // -- 401 everywhere → invalid API key (-12) ----------------------------
    {
        let mut st = mock.state.lock().unwrap();
        st.license_case = "rs256-trial-valid".to_string();
        st.fail_status = Some(401);
        st.fail_body.clear();
    }
    {
        let mut c = client(&jwks, &mock.base_url, None).unwrap();
        let err = c.check().expect_err("401 must fail");
        assert_eq!(err.code, -12, "invalid api key: {err}");
    }

    // -- 402 trial_quota → trial quota exceeded (-13) with detail ----------
    {
        let mut st = mock.state.lock().unwrap();
        st.fail_status = Some(402);
        st.fail_body =
            r#"{"error":"trial_quota","detail":"Active-trial quota exhausted."}"#.to_string();
    }
    {
        let mut c = client(&jwks, &mock.base_url, None).unwrap();
        let err = c.check().expect_err("402 must fail");
        assert_eq!(err.code, -13, "trial quota: {err}");
        assert!(err.detail.contains("quota"), "detail: {}", err.detail);
    }

    // -- dead URL without cache → network failure (-7) ----------------------
    {
        let mut c = client(&jwks, dead_base, None).unwrap();
        let err = c.check().expect_err("dead URL without cache must fail");
        assert_eq!(err.code, -7, "network failure: {err}");
    }
}
