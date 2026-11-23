package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestProviderGrantRevocationReceiptMigrationForwardOnlyHistory(t *testing.T) {
	for _, version := range []migrations.Version{1, 380, migrations.Version(math.MaxInt64)} {
		history, err := (ProviderGrantRevocationReceiptMigrationSource{Version: version}).Load(t.Context())
		if err != nil || len(history) != 1 {
			t.Fatal("supported version did not return one receipt migration", version, err)
		}
		m := history[0]
		if m.Version() != version || m.Name() != "sso_provider_grant_revocation_receipts" ||
			m.TransactionMode() != migrations.TransactionModeDefault || m.UpSQL() == "" || m.DownSQL() != "" {
			t.Fatal("receipt migration lost caller-selected forward-only history")
		}
	}
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1} {
		if history, err := (ProviderGrantRevocationReceiptMigrationSource{Version: version}).Load(t.Context()); history != nil || !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("invalid version returned receipt history", err)
		}
	}
	source := ProviderGrantRevocationReceiptMigrationSource{Version: 380}
	if history, err := source.Load(nil); history != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("nil context returned receipt history", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := source.Load(ctx); history != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context returned receipt history", err)
	}
}

func TestScanProviderGrantRevocationReceiptPreservesClosedOutcomesAndUint64(t *testing.T) {
	for _, outcome := range []providerGrantRevocationOutcome{providerGrantAcknowledged, providerGrantRefused, providerGrantUnknown, providerGrantNotSent} {
		t.Run(string(outcome), func(t *testing.T) {
			row := providerGrantRevocationReceiptRowFixture()
			row.outcome, row.erased = string(outcome), outcome == providerGrantAcknowledged
			receipt, err := scanProviderGrantRevocationReceipt(row)
			if err != nil || receipt.Tenant != "tenant" || receipt.User != "user" || receipt.Version != math.MaxUint64 ||
				receipt.Generation != math.MaxUint64 || receipt.Callback != "AQAAAAAAAAAAAAAAAAAAAA" ||
				receipt.Attempt != "AgAAAAAAAAAAAAAAAAAAAA" || receipt.IntentDigest != ([32]byte{3}) ||
				receipt.Outcome != outcome || receipt.LocalErased != row.erased {
				t.Fatal("receipt scan changed the original grant, attempt or outcome", err)
			}
		})
	}
}

func TestScanProviderGrantRevocationReceiptRejectsMalformedStorage(t *testing.T) {
	for name, mutate := range map[string]func(*providerGrantRevocationReceiptTestRow){
		"missing tenant":          func(r *providerGrantRevocationReceiptTestRow) { r.tenant = "" },
		"missing user":            func(r *providerGrantRevocationReceiptTestRow) { r.user = "" },
		"short callback":          func(r *providerGrantRevocationReceiptTestRow) { r.callback = []byte{1} },
		"zero callback":           func(r *providerGrantRevocationReceiptTestRow) { r.callback = make([]byte, 16) },
		"short attempt":           func(r *providerGrantRevocationReceiptTestRow) { r.attempt = []byte{2} },
		"zero attempt":            func(r *providerGrantRevocationReceiptTestRow) { r.attempt = make([]byte, 16) },
		"same command":            func(r *providerGrantRevocationReceiptTestRow) { r.attempt = r.callback },
		"zero version":            func(r *providerGrantRevocationReceiptTestRow) { r.version = "0" },
		"negative version":        func(r *providerGrantRevocationReceiptTestRow) { r.version = "-1" },
		"overflow version":        func(r *providerGrantRevocationReceiptTestRow) { r.version = "18446744073709551616" },
		"noncanonical version":    func(r *providerGrantRevocationReceiptTestRow) { r.version = "01" },
		"zero generation":         func(r *providerGrantRevocationReceiptTestRow) { r.generation = "0" },
		"overflow generation":     func(r *providerGrantRevocationReceiptTestRow) { r.generation = "18446744073709551616" },
		"noncanonical generation": func(r *providerGrantRevocationReceiptTestRow) { r.generation = "01" },
		"short digest":            func(r *providerGrantRevocationReceiptTestRow) { r.digest = []byte{3} },
		"zero digest":             func(r *providerGrantRevocationReceiptTestRow) { r.digest = make([]byte, 32) },
		"raw provider result":     func(r *providerGrantRevocationReceiptTestRow) { r.outcome = "upstream detail" },
		"acknowledged retained":   func(r *providerGrantRevocationReceiptTestRow) { r.erased = false },
		"refused erased":          func(r *providerGrantRevocationReceiptTestRow) { r.outcome = "refused" },
	} {
		t.Run(name, func(t *testing.T) {
			row := providerGrantRevocationReceiptRowFixture()
			mutate(row)
			receipt, err := scanProviderGrantRevocationReceipt(row)
			if err == nil || receipt != (providerGrantRevocationReceipt{}) {
				t.Fatal("malformed receipt returned usable history")
			}
		})
	}
}

func TestScanProviderGrantRevocationReceiptPreservesReadFailure(t *testing.T) {
	failure := errors.New("receipt read failed")
	row := providerGrantRevocationReceiptRowFixture()
	row.err = failure
	if receipt, err := scanProviderGrantRevocationReceipt(row); !errors.Is(err, failure) || receipt != (providerGrantRevocationReceipt{}) {
		t.Fatal("scan failure became an outcome", err)
	}
	if receipt, err := scanProviderGrantRevocationReceipt(nil); err == nil || receipt != (providerGrantRevocationReceipt{}) {
		t.Fatal("nil row became an outcome")
	}
}

type providerGrantRevocationReceiptTestRow struct {
	tenant, user        string
	callback, attempt   []byte
	version, generation string
	digest              []byte
	outcome             string
	erased              bool
	err                 error
}

func providerGrantRevocationReceiptRowFixture() *providerGrantRevocationReceiptTestRow {
	callback, attempt, digest := make([]byte, 16), make([]byte, 16), make([]byte, 32)
	callback[0], attempt[0], digest[0] = 1, 2, 3
	return &providerGrantRevocationReceiptTestRow{
		tenant: "tenant", user: "user", callback: callback, attempt: attempt,
		version: "18446744073709551615", generation: "18446744073709551615", digest: digest,
		outcome: "acknowledged", erased: true,
	}
}

func (r *providerGrantRevocationReceiptTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string), *dest[1].(*string) = r.tenant, r.user
	*dest[2].(*[]byte), *dest[3].(*[]byte) = r.callback, r.attempt
	*dest[4].(*string), *dest[5].(*string) = r.version, r.generation
	*dest[6].(*[]byte), *dest[7].(*string), *dest[8].(*bool) = r.digest, r.outcome, r.erased
	return nil
}
