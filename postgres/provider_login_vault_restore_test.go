package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func TestProviderLoginVaultRestoresOAuth2FromCommittedRowProjection(t *testing.T) {
	service, found, command, tokens := providerLoginOAuth2VaultFixture(t, true, true)
	service.config.RestorableOAuth2Vault = true
	prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
	if err != nil {
		t.Fatal("the original provider exchange could not deposit custody", err)
	}
	changed := prepared
	changed.BindingWireDigest[0] ^= 1
	if service.validateProviderLoginTokens(t.Context(), changed) == nil {
		t.Fatal("v2 lost the original callback provenance check")
	}
	service.config.RestorableOAuth2Vault = false
	if err := service.validateProviderLoginTokens(t.Context(), prepared); err != nil {
		t.Fatal("disabling new writes stranded a pending v2 preparation", err)
	}
	// Drop all temporary callback facts. This is the exact data the vault row
	// retains after original executable callback custody has been erased.
	row, ciphertext := prepared.storedTokenBinding(), bytes.Clone(prepared.Ciphertext)
	t.Cleanup(func() { clear(ciphertext) })
	found, prepared = providerLoginCallbackLookup{}, providerLoginPreparedTokens{}
	reopened := &ProviderLoginService{payload: service.payload}
	var retained [][]byte
	err = reopened.borrowStoredOAuth2Tokens(t.Context(), row, ciphertext, func(_ context.Context, access, refresh []byte) error {
		if !bytes.Equal(access, []byte("synthetic-oauth-access")) || !bytes.Equal(refresh, []byte("synthetic-oauth-refresh")) {
			t.Fatal("reopened row lost the original access or refresh custody")
		}
		retained = append(retained, access, refresh)
		return nil
	})
	if err != nil || len(retained) != 2 {
		t.Fatal("durable row alone failed exact original custody restoration", err)
	}
	for _, token := range retained {
		if !bytes.Equal(token, make([]byte, len(token))) {
			t.Fatal("borrowing could outlive the restore boundary")
		}
	}
	for name, change := range map[string]func(*providerLoginStoredTokenBinding){
		"organization": func(p *providerLoginStoredTokenBinding) { p.Organization = "foreign-organization" },
		"tenant":       func(p *providerLoginStoredTokenBinding) { p.Account.TenantID = "foreign-tenant" },
		"subject":      func(p *providerLoginStoredTokenBinding) { p.Account.Subject = "another-subject" },
		"provider":     func(p *providerLoginStoredTokenBinding) { p.Provider = "another-provider" },
		"generation":   func(p *providerLoginStoredTokenBinding) { p.CredentialGeneration++ },
		"version":      func(p *providerLoginStoredTokenBinding) { p.Version++ },
		"cutoff":       func(p *providerLoginStoredTokenBinding) { p.AccessExpiresAt = p.AccessExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			altered := row
			change(&altered)
			if reopened.borrowStoredOAuth2Tokens(t.Context(), altered, ciphertext, func(context.Context, []byte, []byte) error {
				t.Fatal("a substituted row reached the original tokens")
				return nil
			}) == nil {
				t.Fatal("an altered durable row was accepted")
			}
		})
	}
}

func TestProviderLoginVaultRestoresOAuth2RejectsLegacyDeposit(t *testing.T) {
	service, found, command, tokens := providerLoginOAuth2VaultFixture(t, true, true)
	prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
	if err != nil || prepared.EnvelopeVersion != 0 {
		t.Fatal("default OAuth2 callback did not write legacy custody", err)
	}
	if err := service.validateProviderLoginTokens(t.Context(), prepared); err != nil {
		t.Fatal("legacy custody failed during original callback", err)
	}
	err = service.borrowStoredOAuth2Tokens(t.Context(), prepared.storedTokenBinding(), prepared.Ciphertext, func(context.Context, []byte, []byte) error {
		t.Fatal("legacy custody opened without retained callback provenance")
		return nil
	})
	if err == nil {
		t.Fatal("legacy deposit was accepted by the durable reader")
	}
}

func TestProviderLoginVaultRestoresOAuth2BoundsBorrowing(t *testing.T) {
	service, found, command, tokens := providerLoginOAuth2VaultFixture(t, true, true)
	service.config.RestorableOAuth2Vault = true
	prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	row := prepared.storedTokenBinding()
	aad, err := row.aad()
	if err != nil {
		t.Fatal(err)
	}
	origin := sha256.Sum256([]byte("synthetic-provenance"))
	prefix := append([]byte(providerLoginStoredTokenHeader), origin[:]...)
	wire := func(accessLen int) []byte {
		frame := binary.BigEndian.AppendUint32(bytes.Clone(prefix), uint32(accessLen))
		frame = append(frame, bytes.Repeat([]byte{'a'}, accessLen)...)
		return binary.BigEndian.AppendUint32(frame, 0)
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		valid bool
	}{
		{"exact limit, no refresh", wire(16 << 10), true},
		{"oversize access", wire(16<<10 + 1), false},
		{"empty access", wire(0), false},
		{"short commitment", prefix[:len(prefix)-1], false},
		{"missing refresh length", wire(1)[:len(prefix)+5], false},
		{"trailing byte", append(wire(1), 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := service.payload.seal(t.Context(), aad, tc.frame, 65536)
			if err != nil {
				t.Fatal("seal independent fixture", err)
			}
			borrowed := false
			err = service.borrowStoredOAuth2Tokens(t.Context(), row, sealed, func(_ context.Context, access, refresh []byte) error {
				borrowed = true
				if !tc.valid || len(access) != 16<<10 || len(refresh) != 0 || cap(access) != len(access) || cap(refresh) != 0 {
					t.Fatal("borrowed tokens outside the exact frame bounds")
				}
				return nil
			})
			if borrowed != tc.valid || (err == nil) != tc.valid {
				t.Fatal("unexpected durable frame admission", err)
			}
		})
	}
}
