// Package hymmalm is the Go wrapper for license-management-core.
//
// It is a thin cgo binding over the native hymmalm shared library
// (include/hymma/hlm_ffi.h). All licensing logic — JWS verification,
// status rules, machine fingerprinting, the REST client flow, retry
// policy and clock-tamper resistance — lives in the native core, so
// every language wrapper behaves identically. This package only
// marshals.
//
// Typical use:
//
//	client, err := hymmalm.New(hymmalm.Options{
//	    ProductID:    "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
//	    ClientAPIKey: "PUB_...", // never a MST_ key
//	    JwksJSON:     jwks,      // from /api/signingkeys.json
//	    LicensePath:  licPath,   // offline .lic cache
//	})
//	if err != nil { ... }
//	defer client.Close()
//
//	status, err := client.Check() // trial bootstrap on first run
//	if status == hymmalm.StatusInvalidTrial {
//	    status, err = client.Activate(userEnteredReceiptCode)
//	}
//
// Thread-safety follows the native handle: one *Client per goroutine,
// or serialize calls yourself.
package hymmalm

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../build -lhymmalm -Wl,-rpath,${SRCDIR}/../../build
#include <stdlib.h>
#include "hymma/hlm_ffi.h"
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

// Status mirrors the native hlm_status / the .NET SDK's LicenseStatusTitles.
type Status int

const (
	StatusUnknown             Status = 0
	StatusExpired             Status = 1
	StatusValid               Status = 2
	StatusValidTrial          Status = 3
	StatusInvalidTrial        Status = 4
	StatusReceiptExpired      Status = 5
	StatusReceiptUnregistered Status = 6
)

// String returns the canonical status name as the server spells it.
func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "Unknown"
	case StatusExpired:
		return "Expired"
	case StatusValid:
		return "Valid"
	case StatusValidTrial:
		return "ValidTrial"
	case StatusInvalidTrial:
		return "InvalidTrial"
	case StatusReceiptExpired:
		return "ReceiptExpired"
	case StatusReceiptUnregistered:
		return "ReceiptUnregistered"
	}
	return "Status(" + itoa(int(s)) + ")"
}

// Format identifies the signed-license wire formats the server can emit.
type Format int

const (
	FormatRS256 Format = 1
	FormatES256 Format = 2
	FormatEdDSA Format = 3
)

// Classified reasons the core or the server can refuse an operation
// (values of Error.Code).
const (
	ErrInvalidArgument      = -1
	ErrBufferTooSmall       = -2
	ErrMalformedInput       = -3
	ErrSignatureInvalid     = -4
	ErrUnsupportedAlgorithm = -5
	ErrNoLicense            = -6
	ErrNetworkFailure       = -7
	ErrAPIRejected          = -8
	ErrStorageFailure       = -9
	ErrProductMismatch      = -10
	ErrComputerMismatch     = -11
	ErrInvalidAPIKey        = -12
	ErrTrialQuotaExceeded   = -13
	ErrPaidFormatRequired   = -14
	ErrPlanLimitReached     = -15
)

// Error is returned when the native core reports an error. Code is one of
// the Err* constants; Detail carries the server's human-readable refusal
// reason when it sent one. Check for it with errors.As:
//
//	var lerr *hymmalm.Error
//	if errors.As(err, &lerr) && lerr.Code == hymmalm.ErrInvalidAPIKey { ... }
type Error struct {
	Code   int
	Detail string
}

func (e *Error) Error() string {
	name := C.GoString(C.hlm_ffi_err_name(C.int(e.Code)))
	if e.Detail != "" {
		return name + ": " + e.Detail
	}
	return name
}

// timeNone is the native HLM_TIME_NONE sentinel (INT64_MIN).
const timeNone = -1 << 63

// ------------------------------------------------------------------ //
// cgo marshalling helpers                                             //
// ------------------------------------------------------------------ //

// cOpt converts a Go string to a C string, mapping "" to NULL so the
// native defaults apply for optional parameters.
func cOpt(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func cFree(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// goStr copies a borrowed const char* from the library immediately;
// NULL maps to "".
func goStr(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

func fromUnix(v C.int64_t) (time.Time, bool) {
	if int64(v) == timeNone {
		return time.Time{}, false
	}
	return time.Unix(int64(v), 0).UTC(), true
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [24]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ------------------------------------------------------------------ //
// package-level helpers                                               //
// ------------------------------------------------------------------ //

// MachineID returns this machine's hardware fingerprint (52-char
// Crockford Base32) — identical to the .NET SDK's DeviceId on the same
// machine.
func MachineID() (string, error) {
	buf := (*C.char)(C.malloc(64))
	defer C.free(unsafe.Pointer(buf))
	if r := C.hlm_ffi_machine_id(buf, 64); r != 0 {
		return "", &Error{Code: int(r)}
	}
	return C.GoString(buf), nil
}

// MachineName returns this computer's name, as the SDK would send it.
func MachineName() (string, error) {
	buf := (*C.char)(C.malloc(256))
	defer C.free(unsafe.Pointer(buf))
	if r := C.hlm_ffi_machine_name(buf, 256); r != 0 {
		return "", &Error{Code: int(r)}
	}
	return C.GoString(buf), nil
}

// Verify is the offline one-shot: it verifies a signed license string
// against jwksJSON and reports its status at now (pass the zero
// time.Time for the system clock). expectedProductID and
// expectedMachineID are optional binding checks; pass "" to skip.
// It returns a *Error when the string is tampered or malformed.
func Verify(jws, jwksJSON, expectedProductID, expectedMachineID string, now time.Time) (Status, error) {
	cJws := C.CString(jws)
	defer C.free(unsafe.Pointer(cJws))
	cJwks := C.CString(jwksJSON)
	defer C.free(unsafe.Pointer(cJwks))
	cProd := cOpt(expectedProductID)
	defer cFree(cProd)
	cMach := cOpt(expectedMachineID)
	defer cFree(cMach)

	var unix C.int64_t
	if !now.IsZero() {
		unix = C.int64_t(now.Unix())
	}
	var status C.int
	if r := C.hlm_ffi_verify(cJws, cJwks, cProd, cMach, unix, &status); r != 0 {
		return StatusUnknown, &Error{Code: int(r)}
	}
	return Status(status), nil
}

// ------------------------------------------------------------------ //
// client                                                              //
// ------------------------------------------------------------------ //

// Options configures a Client. ProductID, ClientAPIKey and JwksJSON are
// required; empty optional strings select the native defaults
// (production BaseURL, hardware MachineID, this computer's MachineName,
// no offline cache).
type Options struct {
	BaseURL      string // "" => https://license-management.com/api/
	ProductID    string // required (PRD_...)
	ClientAPIKey string // required (PUB_..., never MST_)
	JwksJSON     string // required: one JWK object or a JSON array of JWKs
	Format       Format // 0 => FormatRS256
	ValidDays    uint   // 0 => 90
	MachineID    string // "" => derive from hardware
	MachineName  string // "" => this computer's name
	LicensePath  string // "" => no offline cache; else the .lic cache file
}

// Client is the high-level licensing client
// (Check / Activate / Deactivate / Refresh). One instance per goroutine,
// or serialize calls yourself — same rule as the native handle it wraps.
type Client struct {
	h *C.hlm_ffi_client
}

// New creates a Client from opts. It fails when the native core rejects
// the options (missing product/key/JWKS, or no machine fingerprint
// available on this platform).
func New(opts Options) (*Client, error) {
	format := opts.Format
	if format == 0 {
		format = FormatRS256
	}

	cBase := cOpt(opts.BaseURL)
	defer cFree(cBase)
	cProd := cOpt(opts.ProductID)
	defer cFree(cProd)
	cKey := cOpt(opts.ClientAPIKey)
	defer cFree(cKey)
	cJwks := cOpt(opts.JwksJSON)
	defer cFree(cJwks)
	cMachID := cOpt(opts.MachineID)
	defer cFree(cMachID)
	cMachName := cOpt(opts.MachineName)
	defer cFree(cMachName)
	cPath := cOpt(opts.LicensePath)
	defer cFree(cPath)

	h := C.hlm_ffi_create(cBase, cProd, cKey, cJwks, C.int(format),
		C.uint(opts.ValidDays), cMachID, cMachName, cPath)
	if h == nil {
		return nil, errors.New("hymmalm: hlm_ffi_create rejected the options " +
			"(missing product/key/JWKS, or no machine fingerprint available " +
			"on this platform)")
	}
	return &Client{h: h}, nil
}

// Close destroys the native handle. Safe to call more than once.
func (c *Client) Close() {
	if c.h != nil {
		C.hlm_ffi_destroy(c.h)
		c.h = nil
	}
}

// op turns a native return code into (Status, error), attaching the
// server's refusal detail when the call failed.
func (c *Client) op(r C.int) (Status, error) {
	if r != 0 {
		detail := goStr(C.hlm_ffi_last_error_detail(c.h))
		return c.Status(), &Error{Code: int(r), Detail: detail}
	}
	return c.Status(), nil
}

// Check performs the silent check; on a fresh machine it also
// bootstraps the trial.
func (c *Client) Check() (Status, error) {
	return c.op(C.hlm_ffi_check(c.h))
}

// Activate attaches a purchased receipt code to this machine's license,
// then refreshes.
func (c *Client) Activate(receiptCode string) (Status, error) {
	cCode := cOpt(receiptCode)
	defer cFree(cCode)
	return c.op(C.hlm_ffi_activate(c.h, cCode))
}

// Deactivate frees this machine's seat (uninstall flow).
func (c *Client) Deactivate() (Status, error) {
	return c.op(C.hlm_ffi_deactivate(c.h))
}

// Refresh force-fetches a fresh signed license, ignoring the cache.
func (c *Client) Refresh() (Status, error) {
	return c.op(C.hlm_ffi_refresh(c.h))
}

// -- state accessors: valid after a successful Check/Activate/Refresh -- //

// Status reports the last evaluated license status.
func (c *Client) Status() Status {
	return Status(C.hlm_ffi_status(c.h))
}

// LicenseID returns the license id (LIC_...).
func (c *Client) LicenseID() string {
	return goStr(C.hlm_ffi_license_id(c.h))
}

// ProductName returns the product's display name.
func (c *Client) ProductName() string {
	return goStr(C.hlm_ffi_product_name(c.h))
}

// BuyerEmail returns the buyer's email once a receipt is attached.
func (c *Client) BuyerEmail() string {
	return goStr(C.hlm_ffi_buyer_email(c.h))
}

// LiveMode reports whether the license was issued in live (vs test) mode.
func (c *Client) LiveMode() bool {
	return C.hlm_ffi_live_mode(c.h) != 0
}

// Expires returns the license expiry; ok is false when the license
// carries no expiry.
func (c *Client) Expires() (time.Time, bool) {
	return fromUnix(C.hlm_ffi_expires(c.h))
}

// TrialEnd returns the trial end; ok is false when there is none.
func (c *Client) TrialEnd() (time.Time, bool) {
	return fromUnix(C.hlm_ffi_trial_end(c.h))
}

// ReceiptExpires returns the receipt expiry; ok is false when there is
// none.
func (c *Client) ReceiptExpires() (time.Time, bool) {
	return fromUnix(C.hlm_ffi_receipt_expires(c.h))
}

// Metadata returns the value of a vendor metadata key on the license,
// or "" when absent.
func (c *Client) Metadata(key string) string {
	cKey := cOpt(key)
	defer cFree(cKey)
	return goStr(C.hlm_ffi_metadata(c.h, cKey))
}

// LastHTTPStatus returns the HTTP status of the last API call made by
// this handle (0 when none).
func (c *Client) LastHTTPStatus() int {
	return int(C.hlm_ffi_last_http_status(c.h))
}
