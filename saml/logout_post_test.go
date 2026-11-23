package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const logoutPOSTDestination = "https://login.example/saml2/test/slo"

// Core §§3.7.1, 3.7.3; Profiles §4.4.4.1: only an authenticated IdP
// request carries targets. Optional qualifiers are preserved, never inferred.
func TestLogoutPOSTRequestPreservesSignedTargets(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	for _, format := range []string{samlPersistentNameID, samlEmailNameID} {
		for _, qualifiers := range []string{"", ` NameQualifier="` + fixtureIdP + `" SPNameQualifier="` + fixtureSP + `"`} {
			for _, session := range []string{"", `<p:SessionIndex>private-session</p:SessionIndex>`} {
				subject := `<a:NameID xmlns:a="` + samlAssertionNS + `" Format="` + format + `"` + qualifiers + `>private-subject</a:NameID>`
				xml := logoutPOSTFixture(t, key, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ""), subject+session)
				verified, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(xml)}, Now: now})
				if err != nil {
					t.Fatal("signed selected request rejected", err)
				}
				request, err := verified.Request()
				if err != nil || verified.Kind() != LogoutPOSTRequest || request.ID != "_logout" || request.ProviderSubject != "private-subject" || request.SubjectFormat != format || request.IssuedAt != now.Add(-time.Minute) || !request.ValidUntil.Equal(now.Add(time.Minute)) {
					t.Fatal("signed request evidence changed")
				}
				if (request.NameQualifier == fixtureIdP) != (qualifiers != "") || (request.SPNameQualifier == fixtureSP) != (qualifiers != "") || (request.SessionIndex == "private-session") != (session != "") {
					t.Fatal("optional signed context changed")
				}
				if _, err := verified.Response(); !errors.Is(err, ErrInvalidInput) {
					t.Fatal("request projected as response")
				}
			}
		}
	}
}

// Core §§3.2.2, 3.2.2.1, 3.2.2.2, 3.7.2, 3.7.3.2; Profiles §4.4.4.2:
// signed status is evidence, not a guarantee of local or remote revocation.
func TestLogoutPOSTResponseReturnsSignedStatusAndCorrelation(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	for _, code := range []LogoutStatusCode{LogoutStatusSuccess, LogoutStatusRequester, LogoutStatusResponder, LogoutStatusVersionMismatch} {
		for _, subcode := range []LogoutStatusCode{"", LogoutStatusPartialLogout, LogoutStatusUnknownPrincipal, LogoutStatusRequestDenied, LogoutStatusUnsupportedBinding} {
			if code == LogoutStatusSuccess && subcode != "" && subcode != LogoutStatusPartialLogout {
				continue
			}
			xml := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), logoutPOSTStatus(string(code), string(subcode)))
			verified, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLResponse: []string{logoutPOSTEncoded(xml)}, Now: now})
			if err != nil {
				t.Fatal("signed status rejected", err)
			}
			response, err := verified.Response()
			if err != nil || verified.Kind() != LogoutPOSTResponse || response.ID != "_logout" || response.InResponseTo != "_outstanding" || response.Status.Code != code || response.Status.Subcode != subcode || !response.ValidUntil.Equal(now.Add(time.Minute)) {
				t.Fatal("signed response evidence changed")
			}
			if _, err := verified.Request(); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("response projected as request")
			}
		}
	}
}

// Core §3.2.2.1 permits an optional diagnostic after StatusCode. It is
// authenticated but carries no authority and must not change signed evidence.
func TestLogoutPOSTResponseAcceptsAndDiscardsBoundedSignedStatusMessage(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	status := logoutPOSTStatus(string(LogoutStatusResponder), string(LogoutStatusRequestDenied))
	baseXML := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), status)
	base, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLResponse: []string{logoutPOSTEncoded(baseXML)}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := base.Response()
	if err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string]string{
		"provider error":         "private-provider-diagnostic",
		"empty diagnostic":       "",
		"plain XML whitespace":   "private-provider\n diagnostic\ttext",
		"exact diagnostic bound": strings.Repeat("x", maximumEndpointBytes),
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(status, "</p:Status>", "<p:StatusMessage>"+message+"</p:StatusMessage></p:Status>", 1)
			xml := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), body)
			verified, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLResponse: []string{logoutPOSTEncoded(xml)}, Now: now})
			if err != nil {
				t.Fatal("legitimate signed provider status with diagnostic rejected", err)
			}
			evidence, err := verified.Response()
			if err != nil || evidence != expected {
				t.Fatal("diagnostic changed signed status or correlation evidence")
			}
			if strings.Contains(fmt.Sprintf("%#v", verified), "private-provider") || strings.Contains(evidence.LogValue().String(), "private-provider") {
				t.Fatal("signed diagnostic escaped redaction")
			}
		})
	}
}

// Core §§3.2.2.1, 3.2.2.2: supporting optional StatusMessage does not
// introduce extension/diagnostic authority or permit arbitrary nested codes.
func TestLogoutPOSTResponseRejectsUnselectedDiagnosticsAndSuccessSubcodes(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	status := logoutPOSTStatus(string(LogoutStatusResponder), string(LogoutStatusRequestDenied))
	for name, diagnostic := range map[string]string{
		"duplicate":           `<p:StatusMessage>one</p:StatusMessage><p:StatusMessage>two</p:StatusMessage>`,
		"wrong namespace":     `<x:StatusMessage xmlns:x="urn:unselected">private-provider</x:StatusMessage>`,
		"no namespace":        `<StatusMessage>private-provider</StatusMessage>`,
		"nested":              `<p:StatusMessage><p:StatusMessage>private-provider</p:StatusMessage></p:StatusMessage>`,
		"attribute":           `<p:StatusMessage Language="en">private-provider</p:StatusMessage>`,
		"qualified attribute": `<p:StatusMessage xml:lang="en">private-provider</p:StatusMessage>`,
		"oversized":           `<p:StatusMessage>` + strings.Repeat("x", maximumEndpointBytes+1) + `</p:StatusMessage>`,
		"status detail":       `<p:StatusDetail></p:StatusDetail>`,
		"extensions":          `<p:Extensions></p:Extensions>`,
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(status, "</p:Status>", diagnostic+"</p:Status>", 1)
			xml := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), body)
			denied, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLResponse: []string{logoutPOSTEncoded(xml)}, Now: now})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatal("unselected diagnostic accepted or exposed", err)
			}
			logoutPOSTAssertDenied(t, denied)
		})
	}
	for _, subcode := range []LogoutStatusCode{LogoutStatusUnknownPrincipal, LogoutStatusRequestDenied, LogoutStatusUnsupportedBinding} {
		xml := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), logoutPOSTStatus(string(LogoutStatusSuccess), string(subcode)))
		denied, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLResponse: []string{logoutPOSTEncoded(xml)}, Now: now})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatal("success accepted an unselected subordinate status", err)
		}
		logoutPOSTAssertDenied(t, denied)
	}
}

// Bindings §§3.5.4, 3.5.5.2; Core §§3.7.1, 3.7.2: field classification
// must match the exact signed document root before extracting a subject.
func TestLogoutPOSTRejectsFieldAmbiguityAndUntrustedXML(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	request := logoutPOSTFixture(t, key, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ""), logoutPOSTSubject())
	response := logoutPOSTFixture(t, key, "LogoutResponse", logoutPOSTAttrs("LogoutResponse", ""), logoutPOSTStatus(samlStatusSuccess, ""))
	for name, input := range map[string]LogoutPOSTInput{
		"none": {}, "empty request": {SAMLRequest: []string{""}},
		"duplicate request":      {SAMLRequest: []string{logoutPOSTEncoded(request), logoutPOSTEncoded(request)}},
		"duplicate response":     {SAMLResponse: []string{logoutPOSTEncoded(response), logoutPOSTEncoded(response)}},
		"both fields":            {SAMLRequest: []string{logoutPOSTEncoded(request)}, SAMLResponse: []string{logoutPOSTEncoded(response)}},
		"response under request": {SAMLRequest: []string{logoutPOSTEncoded(response)}},
		"request under response": {SAMLResponse: []string{logoutPOSTEncoded(request)}},
		"bad base64":             {SAMLRequest: []string{"not-base64"}},
		"oversized base64":       {SAMLRequest: []string{strings.Repeat("A", maximumPOSTBase64Bytes+1)}},
		"oversized decoded":      {SAMLRequest: []string{logoutPOSTEncoded(strings.Repeat("x", maximumSAMLXMLBytes+1))}},
		"DTD":                    {SAMLRequest: []string{logoutPOSTEncoded(`<!DOCTYPE p [<!ENTITY x "private">]>` + request)}},
		"unsigned":               {SAMLRequest: []string{logoutPOSTEncoded(request[:strings.Index(request, "<ds:Signature")] + "</p:LogoutRequest>")}},
		"tampered":               {SAMLRequest: []string{logoutPOSTEncoded(strings.ReplaceAll(request, "private-subject", "other-subject"))}},
	} {
		t.Run(name, func(t *testing.T) {
			input.Now = now
			denied, err := profile.Validate(context.Background(), input)
			if err == nil {
				t.Fatal("untrusted field/XML accepted")
			}
			logoutPOSTAssertDenied(t, denied)
		})
	}
	if _, err := profile.Validate(nil, LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(request)}, Now: now}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := profile.Validate(ctx, LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(request)}, Now: now}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

// Core §§3.2.1, 3.2.2, 3.7.1, 3.7.2; Profiles §§4.4.4.1, 4.4.4.2.
// Re-sign malformed shapes so rejection cannot be explained by stale digests.
func TestLogoutPOSTRejectsSignedWrongAuthorityAndShape(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	requestAttrs := logoutPOSTAttrs("LogoutRequest", "")
	responseAttrs := logoutPOSTAttrs("LogoutResponse", "")
	tests := []struct{ name, root, attrs, body string }{
		{"wrong destination", "LogoutRequest", strings.ReplaceAll(requestAttrs, logoutPOSTDestination, logoutPOSTDestination+"/"), logoutPOSTSubject()},
		{"request correlation", "LogoutRequest", strings.ReplaceAll(requestAttrs, ` IssueInstant=`, ` InResponseTo="_outstanding" IssueInstant=`), logoutPOSTSubject()},
		{"missing response correlation", "LogoutResponse", strings.ReplaceAll(responseAttrs, ` InResponseTo="_outstanding"`, ""), logoutPOSTStatus(samlStatusSuccess, "")},
		{"invalid correlation", "LogoutResponse", strings.ReplaceAll(responseAttrs, "_outstanding", "bad id"), logoutPOSTStatus(samlStatusSuccess, "")},
		{"response subject", "LogoutResponse", responseAttrs, logoutPOSTStatus(samlStatusSuccess, "") + logoutPOSTSubject()},
		{"response session", "LogoutResponse", responseAttrs, logoutPOSTStatus(samlStatusSuccess, "") + `<p:SessionIndex>private-session</p:SessionIndex>`},
		{"request status", "LogoutRequest", requestAttrs, logoutPOSTSubject() + logoutPOSTStatus(samlStatusSuccess, "")},
		{"two session indexes", "LogoutRequest", requestAttrs, logoutPOSTSubject() + `<p:SessionIndex>one</p:SessionIndex><p:SessionIndex>two</p:SessionIndex>`},
		{"empty session", "LogoutRequest", requestAttrs, logoutPOSTSubject() + `<p:SessionIndex></p:SessionIndex>`},
		{"missing NameID", "LogoutRequest", requestAttrs, ""},
		{"unsupported NameID format", "LogoutRequest", requestAttrs, strings.ReplaceAll(logoutPOSTSubject(), samlPersistentNameID, "urn:unsupported")},
		{"wrong qualifier", "LogoutRequest", requestAttrs, strings.ReplaceAll(logoutPOSTSubject(), `">private-subject`, `" NameQualifier="urn:other">private-subject`)},
		{"empty qualifier", "LogoutRequest", requestAttrs, strings.ReplaceAll(logoutPOSTSubject(), `">private-subject`, `" NameQualifier="">private-subject`)},
		{"wrong SP qualifier", "LogoutRequest", requestAttrs, strings.ReplaceAll(logoutPOSTSubject(), `">private-subject`, `" SPNameQualifier="https://other.example">private-subject`)},
		{"unsupported reason", "LogoutRequest", strings.ReplaceAll(requestAttrs, ` Version=`, ` Reason="urn:unselected" Version=`), logoutPOSTSubject()},
		{"unknown top status", "LogoutResponse", responseAttrs, logoutPOSTStatus("urn:unselected", "")},
		{"unknown nested status", "LogoutResponse", responseAttrs, logoutPOSTStatus(string(LogoutStatusResponder), "urn:unselected")},
		{"status detail", "LogoutResponse", responseAttrs, strings.ReplaceAll(logoutPOSTStatus(samlStatusSuccess, ""), "</p:Status>", `<p:StatusDetail>private-text</p:StatusDetail></p:Status>`)},
		{"duplicate XML IDs", "LogoutRequest", requestAttrs, strings.ReplaceAll(logoutPOSTSubject(), `">private-subject`, `" ID="_logout">private-subject`)},
		{"login response root", "Response", responseAttrs, logoutPOSTStatus(samlStatusSuccess, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xml := logoutPOSTFixture(t, key, tt.root, tt.attrs, tt.body)
			input := LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(xml)}, Now: now}
			if tt.root != "LogoutRequest" {
				input.SAMLResponse, input.SAMLRequest = input.SAMLRequest, nil
			}
			denied, err := profile.Validate(context.Background(), input)
			if err == nil {
				t.Fatal("signed malformed shape accepted")
			}
			logoutPOSTAssertDenied(t, denied)
		})
	}
	wrongIssuer := logoutPOSTFixture(t, key, "LogoutRequest", requestAttrs, logoutPOSTSubject(), "urn:other:issuer")
	if _, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(wrongIssuer)}, Now: now}); err == nil {
		t.Fatal("wrong issuer accepted")
	}
}

// Core §§3.2.1, 3.2.2, 3.7.1: skew permits future timestamps only;
// local MaximumAge, signed request expiry and certificate cutoffs stay hard.
func TestLogoutPOSTClockAndSigningCertificateBoundaries(t *testing.T) {
	profile, key, now, config := logoutPOSTSetup(t)
	for _, root := range []string{"LogoutRequest", "LogoutResponse"} {
		for _, test := range []struct {
			name          string
			issued, extra string
			at            time.Time
			accepted      bool
		}{
			{"just before max age", "2026-11-23T04:00:00Z", "", now.Add(time.Minute - time.Nanosecond), true},
			{"at max age", "2026-11-23T04:00:00Z", "", now.Add(time.Minute), false},
			{"at future skew", "2026-11-23T04:01:30Z", "", now, true},
			{"beyond future skew", "2026-11-23T04:01:30.000000001Z", "", now, false},
		} {
			t.Run(root+"/"+test.name, func(t *testing.T) {
				attrs := strings.ReplaceAll(logoutPOSTAttrs(root, test.extra), "2026-11-23T04:00:00Z", test.issued)
				body := logoutPOSTSubject()
				if root == "LogoutResponse" {
					body = logoutPOSTStatus(samlStatusSuccess, "")
				}
				xml := logoutPOSTFixture(t, key, root, attrs, body)
				input := LogoutPOSTInput{Now: test.at, SAMLRequest: []string{logoutPOSTEncoded(xml)}}
				if root == "LogoutResponse" {
					input.SAMLResponse, input.SAMLRequest = input.SAMLRequest, nil
				}
				_, err := profile.Validate(context.Background(), input)
				if (err == nil) != test.accepted {
					t.Fatalf("accepted=%v error=%v", test.accepted, err)
				}
			})
		}
	}
	for _, reason := range []string{"", ` Reason="urn:oasis:names:tc:SAML:2.0:logout:user"`, ` Reason="urn:oasis:names:tc:SAML:2.0:logout:admin"`} {
		xml := logoutPOSTFixture(t, key, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ` NotOnOrAfter="2026-11-23T04:01:15Z"`+reason), logoutPOSTSubject())
		for _, at := range []time.Time{now.Add(15*time.Second - time.Nanosecond), now.Add(15 * time.Second)} {
			verified, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(xml)}, Now: at})
			if (err == nil) != at.Before(now.Add(15*time.Second)) {
				t.Fatal("signed request cutoff extended")
			}
			if err == nil {
				request, _ := verified.Request()
				if !request.ValidUntil.Equal(now.Add(15*time.Second)) || !request.NotOnOrAfter.Equal(now.Add(15*time.Second)) {
					t.Fatal("signed expiry lost")
				}
			}
		}
	}
	// The configured leaf set is copied, not borrowed, and another key cannot
	// become trusted through an embedded certificate or a changed input slice.
	config.SigningCertificates[0][0] ^= 0xff
	xml := logoutPOSTFixture(t, key, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ""), logoutPOSTSubject())
	if _, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(xml)}, Now: now}); err != nil {
		t.Fatal("profile borrowed config certificate bytes", err)
	}
	_, other, _, _ := logoutPOSTSetup(t)
	wrong := logoutPOSTFixture(t, other, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ""), logoutPOSTSubject())
	if _, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(wrong)}, Now: now}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("unapproved leaf accepted")
	}
	for _, at := range []time.Time{now.Add(-time.Hour - time.Nanosecond), now.Add(time.Hour)} {
		fresh := logoutPOSTFixture(t, key, "LogoutRequest", strings.ReplaceAll(logoutPOSTAttrs("LogoutRequest", ""), "2026-11-23T04:00:00Z", at.UTC().Format(time.RFC3339Nano)), logoutPOSTSubject())
		if _, err := profile.Validate(context.Background(), LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(fresh)}, Now: at}); !errors.Is(err, ErrInvalidSignature) {
			t.Fatal("certificate validity cutoff extended")
		}
	}
}

func TestLogoutPOSTProfileRejectsInvalidConfigurationAndZeroResults(t *testing.T) {
	_, _, now, config := logoutPOSTSetup(t)
	for _, edit := range []func(*LogoutPOSTConfig){
		func(c *LogoutPOSTConfig) { c.SPEntityID = "" }, func(c *LogoutPOSTConfig) { c.IdentityProviderEntityID = "" },
		func(c *LogoutPOSTConfig) { c.SingleLogoutURL = "http://login.example/slo" }, func(c *LogoutPOSTConfig) { c.SingleLogoutURL = logoutPOSTDestination + "?q=x" },
		func(c *LogoutPOSTConfig) { c.MaximumAge = 0 }, func(c *LogoutPOSTConfig) { c.MaximumAge = 5*time.Minute + time.Nanosecond },
		func(c *LogoutPOSTConfig) { c.ClockSkew = -1 }, func(c *LogoutPOSTConfig) { c.ClockSkew = 5*time.Minute + 1 },
		func(c *LogoutPOSTConfig) { c.SigningCertificates = nil },
	} {
		invalid := config
		edit(&invalid)
		if _, err := NewLogoutPOSTProfile(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid config accepted")
		}
	}
	if denied, err := (LogoutPOSTProfile{}).Validate(context.Background(), LogoutPOSTInput{Now: now}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero profile accepted")
	} else {
		logoutPOSTAssertDenied(t, denied)
	}
	logoutPOSTAssertDenied(t, VerifiedLogoutPOST{})
}

// Bindings §3.5.3: RelayState deliberately has no input at this XML boundary.
// Sensitive subjects, IDs, wire bytes and signed status must not escape by
// implicit logging/serialization; explicit evidence access is the only release.
func TestLogoutPOSTRedactsInputAndEvidence(t *testing.T) {
	profile, key, now, _ := logoutPOSTSetup(t)
	xml := logoutPOSTFixture(t, key, "LogoutRequest", logoutPOSTAttrs("LogoutRequest", ""), logoutPOSTSubject())
	input := LogoutPOSTInput{SAMLRequest: []string{logoutPOSTEncoded(xml)}, Now: now}
	verified, err := profile.Validate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := verified.Request()
	for _, value := range []any{input, verified, request, LogoutPOSTResponseEvidence{ID: "private-id", InResponseTo: "private-correlation"}} {
		if strings.Contains(fmt.Sprintf("%#v", value), "private-") {
			t.Fatal("sensitive formatting")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("implicit serialization accepted", err)
		}
	}
}

// Bindings §§3.5.4, 3.5.5.2; Core §§3.7.1, 3.7.2: mutations cannot
// cross the signed request/response boundary or disclose evidence on denial.
func FuzzLogoutPOSTEnvelopeAndRoot(f *testing.F) {
	profile, key, now, _ := logoutPOSTSetup(f)
	f.Add(false, uint8(0), uint16(0), "")
	f.Add(true, uint8(0), uint16(0), "")
	f.Add(false, uint8(1), uint16(0), "")
	f.Add(true, uint8(2), uint16(8), "<!--untrusted-->")
	f.Add(false, uint8(3), uint16(0), `<!DOCTYPE p [<!ENTITY x "private">]>`)
	f.Add(true, uint8(4), uint16(0), `<p:LogoutRequest>`)
	f.Add(false, uint8(5), uint16(1), "\x00")
	f.Fuzz(func(t *testing.T, response bool, envelope uint8, offset uint16, mutation string) {
		if len(mutation) > 4096 {
			t.Skip()
		}
		root, body := "LogoutRequest", logoutPOSTSubject()
		if response {
			root, body = "LogoutResponse", logoutPOSTStatus(string(LogoutStatusResponder), string(LogoutStatusPartialLogout))
		}
		xml := logoutPOSTFixture(t, key, root, logoutPOSTAttrs(root, ""), body)
		at := int(offset) % (len(xml) + 1)
		xml = xml[:at] + mutation + xml[at:]
		values := []string{logoutPOSTEncoded(xml)}
		input := LogoutPOSTInput{Now: now}
		if response {
			input.SAMLResponse = values
		} else {
			input.SAMLRequest = values
		}
		switch envelope % 6 {
		case 1:
			input.SAMLRequest, input.SAMLResponse = input.SAMLResponse, input.SAMLRequest
		case 2:
			input.SAMLRequest, input.SAMLResponse = values, values
		case 3:
			if response {
				input.SAMLResponse = append(input.SAMLResponse, values[0])
			} else {
				input.SAMLRequest = append(input.SAMLRequest, values[0])
			}
		case 4:
			input.SAMLRequest, input.SAMLResponse = nil, nil
		case 5:
			input.SAMLRequest, input.SAMLResponse = []string{""}, nil
		}
		verified, err := profile.Validate(context.Background(), input)
		if err != nil {
			logoutPOSTAssertDenied(t, verified)
			return
		}
		if envelope%6 != 0 {
			t.Fatal("invalid envelope disclosed evidence")
		}
		if response {
			evidence, err := verified.Response()
			if err != nil || verified.Kind() != LogoutPOSTResponse || evidence.InResponseTo != "_outstanding" || evidence.Status.Code != LogoutStatusResponder || evidence.Status.Subcode != LogoutStatusPartialLogout {
				t.Fatal("response crossed signed classification/status boundary")
			}
			if _, err := verified.Request(); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("response disclosed subject projection")
			}
		} else {
			evidence, err := verified.Request()
			if err != nil || verified.Kind() != LogoutPOSTRequest || evidence.ProviderSubject != "private-subject" || evidence.SessionIndex != "" {
				t.Fatal("request crossed signed subject boundary")
			}
			if _, err := verified.Response(); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("request disclosed status projection")
			}
		}
	})
}

func logoutPOSTSetup(t testing.TB) (LogoutPOSTProfile, *ecdsa.PrivateKey, time.Time, LogoutPOSTConfig) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 4, 1, 0, 0, time.UTC)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(72), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := LogoutPOSTConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP, SingleLogoutURL: logoutPOSTDestination, SigningCertificates: [][]byte{der}, MaximumAge: 2 * time.Minute, ClockSkew: 30 * time.Second}
	profile, err := NewLogoutPOSTProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	return profile, key, now, config
}

func logoutPOSTAttrs(root, optional string) string {
	attrs := ` Destination="` + logoutPOSTDestination + `" ID="_logout"`
	if root == "LogoutResponse" {
		attrs += ` InResponseTo="_outstanding"`
	}
	return attrs + ` IssueInstant="2026-11-23T04:00:00Z"` + optional + ` Version="2.0"`
}
func logoutPOSTSubject() string {
	return `<a:NameID xmlns:a="` + samlAssertionNS + `" Format="` + samlPersistentNameID + `">private-subject</a:NameID>`
}
func logoutPOSTStatus(code, subcode string) string {
	inner := ""
	if subcode != "" {
		inner = `<p:StatusCode Value="` + subcode + `"></p:StatusCode>`
	}
	return `<p:Status><p:StatusCode Value="` + code + `">` + inner + `</p:StatusCode></p:Status>`
}

// The fixture's canonical bytes are written independently of the production
// parser/canonicalizer, and fixtureSignature signs with the standard crypto API.
func logoutPOSTFixture(t *testing.T, key *ecdsa.PrivateKey, root, attrs, body string, issuerValue ...string) string {
	t.Helper()
	open := `<p:` + root + ` xmlns:p="` + samlProtocolNS + `"` + attrs + `>`
	idp := fixtureIdP
	if len(issuerValue) != 0 {
		idp = issuerValue[0]
	}
	issuer := `<a:Issuer xmlns:a="` + samlAssertionNS + `">` + idp + `</a:Issuer>`
	close := `</p:` + root + `>`
	return open + issuer + fixtureSignature(t, "_logout", xmlSignatureECDSAP256, key, open+issuer+body+close) + body + close
}
func logoutPOSTEncoded(xml string) string { return base64.StdEncoding.EncodeToString([]byte(xml)) }
func logoutPOSTAssertDenied(t *testing.T, verified VerifiedLogoutPOST) {
	t.Helper()
	if verified.Kind() != "" {
		t.Fatal("denied result has a kind")
	}
	if _, err := verified.Request(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("denied request disclosed")
	}
	if _, err := verified.Response(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("denied response disclosed")
	}
}
