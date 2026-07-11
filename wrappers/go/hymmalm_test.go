// Vector-driven compatibility tests plus the end-to-end client flow
// against a local mock of the license API — mirrors the Python wrapper's
// tests/test_vectors.py and tests/test_flow.py case for case.
//
// The mock serves the checked-in signed vectors and a fixed GET DateTime
// (2026-07-10T00:00:00Z). HLM_TIMESYNC=off makes the native client
// resolve its trusted evaluation time from that endpoint, so the
// expected statuses are deterministic regardless of the real clock — and
// the server-time fallback of the clock-tamper cascade is exercised on
// every call.
package hymmalm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	vectorDir = "../../tests/vectors"
	product   = "PRD_01KWWPEPM0N070BDAHJ7G09RGV"
	machine   = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG"
	deadURL   = "http://127.0.0.1:1/api/"
)

func TestMain(m *testing.M) {
	// Must be set before the first native client call (see file header).
	os.Setenv("HLM_TIMESYNC", "off")
	os.Exit(m.Run())
}

// ------------------------------------------------------------------ //
// vector loading                                                      //
// ------------------------------------------------------------------ //

type vectorCase struct {
	Name           string  `json:"Name"`
	Jws            string  `json:"Jws"`
	Valid          bool    `json:"Valid"`
	NowUtc         string  `json:"NowUtc"`
	ExpectedStatus string  `json:"ExpectedStatus"`
	LicenseID      *string `json:"LicenseId"`
}

type vectorFile struct {
	RsaJwk json.RawMessage `json:"RsaJwk"`
	EcJwk  json.RawMessage `json:"EcJwk"`
	EdJwk  json.RawMessage `json:"EdJwk"`
	Cases  []vectorCase    `json:"Cases"`
}

var statusByName = map[string]Status{
	"Unknown":             StatusUnknown,
	"Expired":             StatusExpired,
	"Valid":               StatusValid,
	"ValidTrial":          StatusValidTrial,
	"InvalidTrial":        StatusInvalidTrial,
	"ReceiptExpired":      StatusReceiptExpired,
	"ReceiptUnregistered": StatusReceiptUnregistered,
}

func loadVectors(t *testing.T, name string) vectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return v
}

// jwksOf builds the verify JWKS: a JSON array of whichever of
// RsaJwk/EcJwk/EdJwk the vector file has.
func jwksOf(v vectorFile) string {
	var keys []string
	for _, k := range []json.RawMessage{v.RsaJwk, v.EcJwk, v.EdJwk} {
		if len(k) > 0 {
			keys = append(keys, string(k))
		}
	}
	return "[" + strings.Join(keys, ",") + "]"
}

func parseNow(t *testing.T, c vectorCase) time.Time {
	t.Helper()
	if c.NowUtc == "" {
		return time.Time{}
	}
	now, err := time.Parse(time.RFC3339, c.NowUtc)
	if err != nil {
		t.Fatalf("case %s: bad NowUtc %q: %v", c.Name, c.NowUtc, err)
	}
	return now
}

// ------------------------------------------------------------------ //
// vector tests (mirror test_vectors.py)                               //
// ------------------------------------------------------------------ //

func TestAllVectorCases(t *testing.T) {
	for _, fname := range []string{"vectors.json", "vectors-eddsa.json"} {
		vec := loadVectors(t, fname)
		jwks := jwksOf(vec)
		for _, c := range vec.Cases {
			c := c
			t.Run(fname+"/"+c.Name, func(t *testing.T) {
				status, err := Verify(c.Jws, jwks, "", "", parseNow(t, c))
				if c.Valid {
					if err != nil {
						t.Fatalf("verify failed: %v", err)
					}
					if c.ExpectedStatus != "" {
						want, ok := statusByName[c.ExpectedStatus]
						if !ok {
							t.Fatalf("unknown ExpectedStatus %q", c.ExpectedStatus)
						}
						if status != want {
							t.Fatalf("status = %v, want %v", status, want)
						}
					}
				} else {
					if err == nil {
						t.Fatalf("verify accepted a tampered token (status %v)", status)
					}
					var lerr *Error
					if !errors.As(err, &lerr) {
						t.Fatalf("error is %T, want *hymmalm.Error", err)
					}
					if lerr.Code != ErrSignatureInvalid && lerr.Code != ErrMalformedInput {
						t.Fatalf("code = %d, want %d or %d",
							lerr.Code, ErrSignatureInvalid, ErrMalformedInput)
					}
				}
			})
		}
	}
}

func TestProductAndMachineBinding(t *testing.T) {
	vec := loadVectors(t, "vectors.json")
	jwks := jwksOf(vec)
	var trial *vectorCase
	for i := range vec.Cases {
		if vec.Cases[i].Name == "rs256-trial-valid" {
			trial = &vec.Cases[i]
			break
		}
	}
	if trial == nil {
		t.Fatal("case rs256-trial-valid not found")
	}
	now := parseNow(t, *trial)

	status, err := Verify(trial.Jws, jwks, product, machine, now)
	if err != nil {
		t.Fatalf("bound verify failed: %v", err)
	}
	if status != StatusValidTrial {
		t.Fatalf("status = %v, want ValidTrial", status)
	}

	wantCode := func(err error, want int) {
		t.Helper()
		var lerr *Error
		if !errors.As(err, &lerr) {
			t.Fatalf("error is %T (%v), want *hymmalm.Error", err, err)
		}
		if lerr.Code != want {
			t.Fatalf("code = %d, want %d", lerr.Code, want)
		}
	}

	_, err = Verify(trial.Jws, jwks, "PRD_SOMETHINGELSE", machine, now)
	wantCode(err, ErrProductMismatch)

	_, err = Verify(trial.Jws, jwks, product, "WRONGMACHINE", now)
	wantCode(err, ErrComputerMismatch)
}

func TestMachineIdentity(t *testing.T) {
	id, err := MachineID()
	if err != nil {
		t.Fatalf("MachineID: %v", err)
	}
	if len(id) != 52 {
		t.Fatalf("MachineID length = %d (%q), want 52", len(id), id)
	}
	name, err := MachineName()
	if err != nil {
		t.Fatalf("MachineName: %v", err)
	}
	if name == "" {
		t.Fatal("MachineName is empty")
	}
}

func TestErrorNames(t *testing.T) {
	err := &Error{Code: ErrSignatureInvalid}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error message %q does not mention \"signature\"", err.Error())
	}
}

// ------------------------------------------------------------------ //
// mock license API (mirrors test_flow.py's MockApi)                   //
// ------------------------------------------------------------------ //

type mockState struct {
	mu          sync.Mutex
	licenseCase string
	failStatus  int
	failBody    string
}

func startMock(t *testing.T, cases map[string]string) (*mockState, string) {
	t.Helper()
	st := &mockState{licenseCase: "rs256-trial-valid"}

	send := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Length", itoa(len(body)))
		w.WriteHeader(code)
		w.Write([]byte(body))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		failStatus, failBody := st.failStatus, st.failBody
		licenseCase := st.licenseCase
		st.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			if failStatus != 0 {
				if failBody == "" {
					failBody = "{}"
				}
				send(w, failStatus, failBody)
				return
			}
			switch {
			case strings.HasPrefix(r.URL.Path, "/api/DateTime"):
				send(w, 200, `"2026-07-10T00:00:00Z"`)
			case strings.HasPrefix(r.URL.Path, "/api/computer"):
				send(w, 200, `{"id":"PC_01KWVTRYM7AXBT1V56M2N3E3AB"}`)
			case strings.HasPrefix(r.URL.Path, "/api/license"):
				send(w, 200, cases[licenseCase])
			default:
				send(w, 404, "{}")
			}
		case http.MethodPost:
			if failStatus != 0 {
				if failBody == "" {
					failBody = "{}"
				}
				send(w, failStatus, failBody)
				return
			}
			send(w, 201, "{}")
		case http.MethodPatch:
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				send(w, 400, "{}")
				return
			}
			st.mu.Lock()
			if code, ok := req["Code"]; ok && code != nil {
				st.licenseCase = "rs256-paid-valid"
			} else {
				st.licenseCase = "rs256-receipt-unregistered"
			}
			st.mu.Unlock()
			w.WriteHeader(204)
		default:
			send(w, 405, "{}")
		}
	}))
	t.Cleanup(srv.Close)
	return st, srv.URL + "/api/"
}

func vectorJwsByName(t *testing.T) (map[string]string, string) {
	t.Helper()
	vec := loadVectors(t, "vectors.json")
	cases := make(map[string]string, len(vec.Cases))
	for _, c := range vec.Cases {
		cases[c.Name] = c.Jws
	}
	return cases, "[" + string(vec.RsaJwk) + "]"
}

func newFlowClient(t *testing.T, jwks, baseURL, licPath string) *Client {
	t.Helper()
	c, err := New(Options{
		BaseURL:      baseURL,
		ProductID:    product,
		ClientAPIKey: "PUB_test",
		JwksJSON:     jwks,
		Format:       FormatRS256,
		MachineID:    machine,
		MachineName:  "SHOP-FLOOR-01",
		LicensePath:  licPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// ------------------------------------------------------------------ //
// flow tests (mirror test_flow.py)                                    //
// ------------------------------------------------------------------ //

func TestFlowTrialActivateCacheDeactivate(t *testing.T) {
	cases, jwks := vectorJwsByName(t)
	_, base := startMock(t, cases)
	licPath := filepath.Join(t.TempDir(), "flow-test.lic")

	// 1) Fresh machine: silent check bootstraps a trial.
	c := newFlowClient(t, jwks, base, licPath)
	status, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusValidTrial {
		t.Fatalf("Check = %v, want ValidTrial", status)
	}
	if got := c.LicenseID(); got != "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0" {
		t.Fatalf("LicenseID = %q", got)
	}
	if got := c.ProductName(); got != "CADshift Nesting" {
		t.Fatalf("ProductName = %q", got)
	}
	if _, ok := c.TrialEnd(); !ok {
		t.Fatal("TrialEnd missing on a trial license")
	}

	// 2) Activate a purchased receipt code.
	status, err = c.Activate("RCPT-CODE-1234")
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if status != StatusValid {
		t.Fatalf("Activate = %v, want Valid", status)
	}
	if got := c.BuyerEmail(); got != "jane@example.com" {
		t.Fatalf("BuyerEmail = %q", got)
	}
	if got := c.Metadata("seat"); got != "floor-1" {
		t.Fatalf(`Metadata("seat") = %q, want "floor-1"`, got)
	}
	if !c.LiveMode() {
		t.Fatal("LiveMode = false, want true")
	}
	if _, ok := c.Expires(); !ok {
		t.Fatal("Expires missing on a paid license")
	}
	c.Close()

	// 3) A fresh client on a dead URL must surface the cached license.
	offline := newFlowClient(t, jwks, deadURL, licPath)
	status, err = offline.Check()
	if err != nil {
		t.Fatalf("offline Check: %v", err)
	}
	if status != StatusValid {
		t.Fatalf("offline Check = %v, want Valid", status)
	}
	offline.Close()

	// 4) Back online: still valid, then deactivate frees the seat.
	c2 := newFlowClient(t, jwks, base, licPath)
	status, err = c2.Check()
	if err != nil {
		t.Fatalf("Check (online again): %v", err)
	}
	if status != StatusValid {
		t.Fatalf("Check (online again) = %v, want Valid", status)
	}
	status, err = c2.Deactivate()
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if status != StatusReceiptUnregistered {
		t.Fatalf("Deactivate = %v, want ReceiptUnregistered", status)
	}
}

func TestInvalidAPIKey(t *testing.T) {
	cases, jwks := vectorJwsByName(t)
	st, base := startMock(t, cases)
	st.mu.Lock()
	st.failStatus = 401
	st.mu.Unlock()

	c := newFlowClient(t, jwks, base, "")
	_, err := c.Check()
	var lerr *Error
	if !errors.As(err, &lerr) {
		t.Fatalf("Check error is %T (%v), want *hymmalm.Error", err, err)
	}
	if lerr.Code != ErrInvalidAPIKey {
		t.Fatalf("code = %d, want %d (invalid api key)", lerr.Code, ErrInvalidAPIKey)
	}
}

func TestTrialQuotaDetail(t *testing.T) {
	cases, jwks := vectorJwsByName(t)
	st, base := startMock(t, cases)
	st.mu.Lock()
	st.failStatus = 402
	st.failBody = `{"error":"trial_quota","detail":"Active-trial quota exhausted for this vendor."}`
	st.mu.Unlock()

	c := newFlowClient(t, jwks, base, "")
	_, err := c.Check()
	var lerr *Error
	if !errors.As(err, &lerr) {
		t.Fatalf("Check error is %T (%v), want *hymmalm.Error", err, err)
	}
	if lerr.Code != ErrTrialQuotaExceeded {
		t.Fatalf("code = %d, want %d (trial quota exceeded)", lerr.Code, ErrTrialQuotaExceeded)
	}
	if !strings.Contains(lerr.Detail, "quota") {
		t.Fatalf("detail %q does not mention \"quota\"", lerr.Detail)
	}
}

func TestOfflineWithoutCacheReportsNetworkFailure(t *testing.T) {
	_, jwks := vectorJwsByName(t)
	c := newFlowClient(t, jwks, deadURL, "")
	_, err := c.Check()
	var lerr *Error
	if !errors.As(err, &lerr) {
		t.Fatalf("Check error is %T (%v), want *hymmalm.Error", err, err)
	}
	if lerr.Code != ErrNetworkFailure {
		t.Fatalf("code = %d, want %d (network failure)", lerr.Code, ErrNetworkFailure)
	}
}
