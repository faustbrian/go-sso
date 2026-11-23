package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestSAMLIDPConfirmationAuthenticatesExactBrowserPair(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	key := [32]byte{1}
	b := bytes.Repeat([]byte{7}, 32)
	f := bytes.Repeat([]byte{9}, 32)
	credential := func(v []byte) auth.BearerCredential {
		return auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(v))
	}
	a.BrowserDigest, a.FormDigest = samlIDPBrowserCommitments(key, a.KeyVersion, a.Binding, a.Provider, b, f)
	if !authenticateSAMLIDPBrowserPair(a, key, credential(b), credential(f)) {
		t.Fatal("the original independent pair did not authenticate")
	}
	for _, tc := range []struct {
		name          string
		browser, form auth.BearerCredential
	}{
		{"missing form", credential(b), auth.BearerCredential{}},
		{"wrong form", credential(b), credential(bytes.Repeat([]byte{10}, 32))},
		{"wrong browser", credential(bytes.Repeat([]byte{8}, 32)), credential(f)},
		{"swapped roles", credential(f), credential(b)},
		{"padded encoding", auth.NewBearerCredential(base64.URLEncoding.EncodeToString(b)), credential(f)},
		{"noncanonical encoding", auth.NewBearerCredential(credential(b).Token()[:42] + "x"), credential(f)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if authenticateSAMLIDPBrowserPair(a, key, tc.browser, tc.form) {
				t.Fatal("accepted altered browser custody")
			}
		})
	}
	other := a
	other.Binding.TenantID = "another-tenant"
	if authenticateSAMLIDPBrowserPair(other, key, credential(b), credential(f)) {
		t.Fatal("accepted the same pair for another tenant")
	}
	other = a
	other.Provider = "another-provider"
	if authenticateSAMLIDPBrowserPair(other, key, credential(b), credential(f)) {
		t.Fatal("accepted the same pair for another provider")
	}
	if authenticateSAMLIDPBrowserPair(a, [32]byte{2}, credential(b), credential(f)) {
		t.Fatal("accepted the same pair under another key")
	}
}
