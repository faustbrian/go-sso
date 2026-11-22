//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const nativeCallbackRefusalPrivateDescription = "fixture-provider-private-description-not-durable"

// The original native start, provider activation, browser, linked member and
// primary owners are genuine. Only the explicitly configured provider HTTP
// endpoint is controlled; the callback still uses Golib's strict TLS exchange.
func newNativeCallbackRefusalFixture(t *testing.T, status int, providerError string) (nativeCallbackJourneyFixture, <-chan []byte) {
	t.Helper()
	x := newNativeCallbackJourneyFixture(t, "provider-failure")
	secret := nativeCallbackJourneyInstalledSecret(t, x.start)
	t.Cleanup(func() { clear(secret) })
	verifier := make(chan []byte, 1)
	original := x.started.RedirectURI.Query()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := x.posts.Add(1)
		client, encoded, authenticated := r.BasicAuth()
		decoded, decodeErr := url.QueryUnescape(encoded)
		if r.Method != http.MethodPost || r.URL.Path != "/token" || r.Host != nativeCallbackJourneyHost ||
			!authenticated || client != "native-sso-client" || decodeErr != nil || !bytes.Equal([]byte(decoded), secret) || r.ParseForm() != nil {
			t.Error("controlled provider did not receive the exact installed native client request")
			http.Error(w, "fixture request rejected", http.StatusUnauthorized)
			return
		}
		rawVerifier := []byte(r.PostForm.Get("code_verifier"))
		defer clear(rawVerifier)
		challenge := sha256.Sum256(rawVerifier)
		if r.PostForm.Get("code") != "native-enterprise-original-code" || r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("redirect_uri") != x.request.ReceivedRedirectURI ||
			base64.RawURLEncoding.EncodeToString(challenge[:]) != original.Get("code_challenge") {
			t.Error("controlled provider did not receive the original code, redirect and PKCE verifier")
			http.Error(w, "fixture grant rejected", http.StatusBadRequest)
			return
		}
		if attempt == 1 {
			verifier <- bytes.Clone(rawVerifier)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": providerError, "error_description": nativeCallbackRefusalPrivateDescription})
	}))
	certificate, roots := nativeCallbackJourneyTLSCertificate(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != nativeCallbackJourneyHost+":443" {
				return nil, errors.New("fixture refuses a non-pinned provider endpoint")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
	t.Cleanup(transport.CloseIdleConnections)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	profile := x.start.config.Profiles[0]
	x.completion, err = ssopg.NewProviderLoginCompletionService(x.start.service, ssopg.ProviderLoginCompletionConfig{
		Audience: "native-enterprise-app", PolicyNamespace: "users", CSRFKey: x.csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: x.lookup, TokenSize: 32, Cookie: cookie},
		Profiles: []ssopg.StaticOIDCCompletionProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
			Metadata: sso.OIDCStaticMetadataSpec{Issuer: nativeCallbackJourneyIssuer, AuthorizationEndpoint: nativeCallbackJourneyIssuer + "/authorize",
				TokenEndpoint: nativeCallbackJourneyIssuer + "/token", JWKSURI: nativeCallbackJourneyIssuer + "/keys"},
			ClientAuthentication: oauth.ClientSecretBasic, Algorithms: []string{"ES256"},
			Keys: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, HTTPClient: &http.Client{Transport: transport}}},
	})
	if err != nil {
		t.Fatal("compose native callback with its controlled pinned provider response", err)
	}
	return x, verifier
}

type nativeCallbackRefusalCustody struct {
	organization, provider, callback                string
	issued, expires                                 time.Time
	completed                                       *time.Time
	binding, verifier, stateDigest, pkceCommitment  []byte
	journalState                                    string
	finalReceipt, started, output, outputGeneration bool
}

func readNativeCallbackRefusalCustody(t *testing.T, x nativeCallbackJourneyFixture, callback string, command []byte) nativeCallbackRefusalCustody {
	t.Helper()
	var row nativeCallbackRefusalCustody
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
l.organization_id,l.provider_id,l.callback_command_id,l.issued_at,l.expires_at,l.completed_at,
l.binding_envelope,l.verifier_envelope,l.state_digest,l.pkce_commitment,COALESCE(j.state,'absent'),
COALESCE(j.state='aborted' AND j.result_version=1 AND j.result IS NOT NULL AND j.terminal_at IS NOT NULL,false),
j.preparation_started_generation IS NOT NULL,j.preparation_ciphertext IS NOT NULL,j.preparation_ciphertext_generation IS NOT NULL
FROM sso_providers.login_transactions l LEFT JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.purpose='identity.sso.oidc-callback' AND j.command_id=$3
WHERE l.tenant_id=$1 AND l.start_command_id=$2 AND l.callback_command_id=$4`, string(x.start.config.TenantID), x.started.TransactionID, command, callback).
		Scan(&row.organization, &row.provider, &row.callback, &row.issued, &row.expires, &row.completed,
			&row.binding, &row.verifier, &row.stateDigest, &row.pkceCommitment, &row.journalState,
			&row.finalReceipt, &row.started, &row.output, &row.outputGeneration)
	if err != nil {
		t.Fatal("inspect exact original callback custody around provider failure", err)
	}
	return row
}

func TestNativeProviderLoginCallbackProviderFailureDisposition(t *testing.T) {
	for _, test := range []struct {
		name, providerError string
		status              int
		outcome             identity.CommitOutcome
	}{
		{name: "definitive-invalid-grant", status: http.StatusBadRequest, providerError: "invalid_grant", outcome: identity.CommitOutcomeNotCommitted},
		{name: "ambiguous-service-unavailable", status: http.StatusServiceUnavailable, providerError: "temporarily_unavailable", outcome: identity.CommitOutcomeUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			x, observedVerifier := newNativeCallbackRefusalFixture(t, test.status, test.providerError)
			ctx := x.start.enable.f.ctx
			var callback string
			if err := x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT callback_command_id FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).Scan(&callback); err != nil {
				t.Fatal(err)
			}
			command, err := base64.RawURLEncoding.DecodeString(callback)
			if err != nil {
				t.Fatal(err)
			}
			before := readNativeCallbackRefusalCustody(t, x, callback, command)
			effectsBefore := nativeCallbackJourneyDenialEffects(t, x, callback, command)
			if before.completed != nil || len(before.verifier) == 0 || len(before.binding) == 0 ||
				effectsBefore.deposits != 0 || effectsBefore.successAudits != 0 || effectsBefore.sessionEvents != 0 {
				t.Fatal("provider failure fixture is not a genuine pending native callback without success effects")
			}
			got, err := x.completion.SigninCallback(ctx, x.request)
			assertNativeCallbackRefusalWithholdsIssuance(t, got)
			if x.posts.Load() != 1 {
				t.Fatal("provider failure did not follow exactly one original TLS exchange")
			}
			var rawVerifier []byte
			select {
			case rawVerifier = <-observedVerifier:
				defer clear(rawVerifier)
			default:
				t.Fatal("provider did not observe the genuine original PKCE verifier")
			}
			if got.Completion.Outcome != test.outcome {
				t.Fatal("native callback conflated a definitive provider refusal with an ambiguous exchange", err)
			}
			if test.outcome == identity.CommitOutcomeUnknown {
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || string(unknown.CommandID) != callback {
					t.Fatal("attempted ambiguous exchange lost its exact native unknown-outcome classification")
				}
			} else if got.Completion.Validate() != nil || string(got.Completion.Binding.CommandID) != callback {
				t.Fatal("definitive refusal returned no valid original native NotCommitted receipt")
			}
			after := readNativeCallbackRefusalCustody(t, x, callback, command)
			assertNativeCallbackRefusalOriginalBinding(t, before, after)
			if test.outcome == identity.CommitOutcomeNotCommitted {
				if after.completed == nil || len(after.verifier) != 0 || len(after.binding) == 0 || len(after.binding) > 65536 ||
					after.journalState != "aborted" || !after.finalReceipt || after.output || after.outputGeneration {
					t.Fatal("definitive provider refusal failed to retain a bounded terminal correlation and erase original verifier/temporary output")
				}
				if _, err := envelope.ParseEnvelope(after.binding); err != nil {
					t.Fatal("terminal refusal correlation lost its encrypted native custody", err)
				}
			} else if after.completed != nil || !bytes.Equal(after.verifier, before.verifier) || !bytes.Equal(after.binding, before.binding) ||
				after.journalState != "pending" || after.finalReceipt || !after.started {
				t.Fatal("ambiguous provider failure terminalized, discarded or renewed pending original custody")
			}
			if nativeCallbackJourneyDenialEffects(t, x, callback, command) != effectsBefore {
				t.Fatal("provider failure left a session, token deposit or successful login/session lifecycle effect")
			}
			assertNativeCallbackRefusalSecretAbsence(t, x, callback, command, rawVerifier)
			replayed, _ := x.completion.SigninCallback(ctx, x.request)
			assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
			if x.posts.Load() != 1 || replayed.Completion.Outcome == identity.CommitOutcomeCommitted ||
				test.outcome == identity.CommitOutcomeUnknown && replayed.Completion.Outcome == identity.CommitOutcomeNotCommitted {
				t.Fatal("provider-failure replay exchanged again or fabricated successful/known-negative completion")
			}
			replayedCustody := readNativeCallbackRefusalCustody(t, x, callback, command)
			assertNativeCallbackRefusalOriginalBinding(t, after, replayedCustody)
			if (after.completed == nil) != (replayedCustody.completed == nil) || after.completed != nil && !after.completed.Equal(*replayedCustody.completed) ||
				!bytes.Equal(after.verifier, replayedCustody.verifier) || !bytes.Equal(after.binding, replayedCustody.binding) ||
				after.journalState != replayedCustody.journalState || nativeCallbackJourneyDenialEffects(t, x, callback, command) != effectsBefore {
				t.Fatal("provider-failure replay changed original terminal/pending custody or created domain success")
			}
			assertNativeCallbackRefusalSecretAbsence(t, x, callback, command, rawVerifier)
		})
	}
}

func TestNativeProviderLoginCallbackRefusalTerminalFailureKeepsUnknownCustody(t *testing.T) {
	x, observedVerifier := newNativeCallbackRefusalFixture(t, http.StatusBadRequest, "invalid_grant")
	ctx := x.start.enable.f.ctx
	pool := x.start.enable.f.pool.Raw()
	tenant := string(x.start.config.TenantID)
	var callback string
	if err := pool.QueryRow(ctx, `SELECT callback_command_id FROM sso_providers.login_transactions WHERE tenant_id=$1 AND start_command_id=$2`, tenant, x.started.TransactionID).Scan(&callback); err != nil {
		t.Fatal("read original callback before fixture terminal failure", err)
	}
	command, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Fatal(err)
	}
	before := readNativeCallbackRefusalCustody(t, x, callback, command)
	effectsBefore := nativeCallbackJourneyDenialEffects(t, x, callback, command)
	eventsBefore := nativeProviderLoginCounts(t, x.start).events
	if before.completed != nil || len(before.verifier) == 0 || len(before.binding) == 0 ||
		effectsBefore.deposits != 0 || effectsBefore.successAudits != 0 || effectsBefore.sessionEvents != 0 {
		t.Fatal("terminal failure fixture has no genuine pending native callback")
	}

	// The sequence survives the forced rollback so the fixture proves the real
	// terminal UPDATE was reached, not merely an earlier unrelated failure.
	nativeCallbackJourneyExec(t, x.start, `CREATE SEQUENCE sso_providers.fixture_refusal_terminal_attempts`)
	nativeCallbackJourneyExec(t, x.start, `CREATE FUNCTION sso_providers.fixture_refusal_terminal_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.tenant_id::text=TG_ARGV[0] AND OLD.start_command_id::text=TG_ARGV[1]
    AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
  PERFORM nextval('sso_providers.fixture_refusal_terminal_attempts');
  RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='fixture refuses original pending callback terminal update';
 END IF;
 RETURN NEW;
END $$`)
	var installTrigger string
	if err := pool.QueryRow(ctx, `SELECT format('CREATE TRIGGER fixture_refusal_terminal_failure BEFORE UPDATE OF completed_at ON sso_providers.login_transactions FOR EACH ROW EXECUTE FUNCTION sso_providers.fixture_refusal_terminal_failure(%L,%L)',$1::text,$2::text)`, tenant, x.started.TransactionID).Scan(&installTrigger); err != nil {
		t.Fatal("bind fixture terminal failure to the exact original pending row", err)
	}
	nativeCallbackJourneyExec(t, x.start, installTrigger)

	got, callbackErr := x.completion.SigninCallback(ctx, x.request)
	var attemptedTerminal bool
	if err := pool.QueryRow(ctx, `SELECT is_called FROM sso_providers.fixture_refusal_terminal_attempts`).Scan(&attemptedTerminal); err != nil || !attemptedTerminal {
		t.Fatal("definitive TLS refusal did not reach the fixture's forced native RP terminal failure", err)
	}
	var rawVerifier []byte
	select {
	case rawVerifier = <-observedVerifier:
		defer clear(rawVerifier)
	default:
		t.Fatal("terminal failure did not follow the original verified TLS provider exchange")
	}
	assertUnresolvedCustody := func(result ssopg.ProviderLoginCallbackResult, resultErr error, replay bool) {
		t.Helper()
		assertNativeCallbackRefusalWithholdsIssuance(t, result)
		var unknown identity.UnknownCommitError
		unknownOutcome := result.Completion.Outcome == identity.CommitOutcomeUnknown && errors.As(resultErr, &unknown) && string(unknown.CommandID) == callback
		// Replay can observe the original in-progress journal fence without
		// claiming the provider outcome or taking over its marked generation.
		pendingReplay := replay && result.Completion.Outcome == identity.CommitOutcomeInProgress && errors.Is(resultErr, sso.ErrUnavailable)
		if (!unknownOutcome && !pendingReplay) || result.Completion.Validate() != nil || string(result.Completion.Binding.CommandID) != callback || x.posts.Load() != 1 {
			t.Fatal("failed terminal cleanup lost exact unresolved custody or exchanged again")
		}
		after := readNativeCallbackRefusalCustody(t, x, callback, command)
		assertNativeCallbackRefusalOriginalBinding(t, before, after)
		if after.completed != nil || !bytes.Equal(before.verifier, after.verifier) || !bytes.Equal(before.binding, after.binding) ||
			after.journalState != "pending" || !after.started || after.finalReceipt || after.output || after.outputGeneration {
			t.Fatal("failed terminal cleanup changed original custody or durably stranded intermediate refusal ciphertext/generation")
		}
		if nativeCallbackJourneyDenialEffects(t, x, callback, command) != effectsBefore || nativeProviderLoginCounts(t, x.start).events != eventsBefore {
			t.Fatal("failed terminal cleanup created a session, token deposit, successful audit or outbox effect")
		}
		assertNativeCallbackRefusalSecretAbsence(t, x, callback, command, rawVerifier)
	}
	assertUnresolvedCustody(got, callbackErr, false)

	nativeCallbackJourneyExec(t, x.start, `DROP TRIGGER fixture_refusal_terminal_failure ON sso_providers.login_transactions`)
	replayed, replayErr := x.completion.SigninCallback(ctx, x.request)
	assertUnresolvedCustody(replayed, replayErr, true)
}

func assertNativeCallbackRefusalWithholdsIssuance(t *testing.T, result ssopg.ProviderLoginCallbackResult) {
	t.Helper()
	if result.Issuance.Session != (session.Session{}) || result.Issuance.Token != (session.Token{}) || result.Issuance.Cookie.Name != "" ||
		result.CSRF != (session.CSRFToken{}) || result.RedirectURI != "" {
		t.Fatal("failed provider callback disclosed a session, cookie, CSRF or successful redirect")
	}
}

func assertNativeCallbackRefusalOriginalBinding(t *testing.T, original, current nativeCallbackRefusalCustody) {
	t.Helper()
	if current.organization != original.organization || current.provider != original.provider || current.callback != original.callback ||
		!current.issued.Equal(original.issued) || !current.expires.Equal(original.expires) ||
		!bytes.Equal(current.stateDigest, original.stateDigest) || !bytes.Equal(current.pkceCommitment, original.pkceCommitment) {
		t.Fatal("provider-failure handling substituted or renewed the original organization/provider/state/PKCE/lifetime binding")
	}
}

func assertNativeCallbackRefusalSecretAbsence(t *testing.T, x nativeCallbackJourneyFixture, callback string, command, verifier []byte) {
	t.Helper()
	for _, secret := range [][]byte{verifier, []byte("native-enterprise-original-code"), []byte(x.request.Browser.FlowCookie.Token()),
		[]byte("native-enterprise-synthetic-client-secret"), []byte(nativeCallbackRefusalPrivateDescription)} {
		if len(secret) == 0 {
			t.Fatal("provider-failure secret-absence oracle received no original secret")
		}
		var leaked bool
		err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT EXISTS(SELECT 1 FROM (
SELECT binding_envelope AS wire FROM sso_providers.login_transactions WHERE tenant_id=$1 AND start_command_id=$2
UNION ALL SELECT verifier_envelope FROM sso_providers.login_transactions WHERE tenant_id=$1 AND start_command_id=$2 AND verifier_envelope IS NOT NULL
UNION ALL SELECT result FROM identity.commands WHERE tenant_id=$1 AND command_id=$3 AND result IS NOT NULL
UNION ALL SELECT preparation_ciphertext FROM identity.commands WHERE tenant_id=$1 AND command_id=$3 AND preparation_ciphertext IS NOT NULL
UNION ALL SELECT canonical_record FROM audit.records WHERE tenant_id=$1 AND correlation_id=$4
UNION ALL SELECT m.payload FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$3
UNION ALL SELECT token_ciphertext FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$4
) stored WHERE position($5::bytea in wire)>0)`, string(x.start.config.TenantID), x.started.TransactionID, command, callback, secret).Scan(&leaked)
		if err != nil || leaked {
			t.Fatal("provider refusal/ambiguity retained a raw verifier, code, browser/client secret or private provider description", err)
		}
	}
}
