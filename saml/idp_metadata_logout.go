package saml

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
)

// IDPMetadataSingleLogout contains the normal detached login metadata and
// the two exact IdP browser destinations required by the selected SLO profile.
// It is not proof that a provider is enabled or a remote logout succeeded.
type IDPMetadataSingleLogout struct {
	Login              IDPMetadata
	RedirectRequestURL string
	POSTResponseURL    string
}

// ImportIDPMetadataWithSingleLogout also selects one Redirect request endpoint
// and one POST response endpoint from the same approved SAML 2.0 IdP role.
// The POST binding uses ResponseLocation when present and Location otherwise.
// All locations in both selected descriptors must use HTTPS and a hostname in
// allowedHosts. Supply 1..64 distinct bare ASCII DNS names, case-insensitive
// and without a wildcard, port or trailing dot. URL bytes are not normalized.
// This is an offline import with no redirect, DNS resolution or provider write.
// Missing, malformed or ambiguous endpoints return no partial metadata.
func ImportIDPMetadataWithSingleLogout(ctx context.Context, document []byte, expectedEntityID string, approvedSHA256 [32]byte, now time.Time, allowedHosts []string) (IDPMetadataSingleLogout, error) {
	if ctx == nil {
		return IDPMetadataSingleLogout{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return IDPMetadataSingleLogout{}, err
	}
	allowed, err := samlLogoutDestinationHosts(allowedHosts)
	if err != nil {
		return IDPMetadataSingleLogout{}, err
	}
	login, role, err := importApprovedIDPMetadata(ctx, document, expectedEntityID, approvedSHA256, now)
	if err != nil {
		return IDPMetadataSingleLogout{}, err
	}
	redirect, post, err := importIDPLogoutDestinations(ctx, role, allowed)
	if err != nil {
		return IDPMetadataSingleLogout{}, err
	}
	return IDPMetadataSingleLogout{Login: login, RedirectRequestURL: redirect, POSTResponseURL: post}, nil
}

func importIDPLogoutDestinations(ctx context.Context, role *xdm.Node, allowed map[string]struct{}) (redirect, post string, err error) {
	children, ok := samlElementChildren(role, maximumSAMLXMLNodes)
	if !ok {
		return "", "", ErrInvalidInput
	}
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if !samlElement(child, samlMetadataNamespace, "SingleLogoutService") {
			continue
		}
		binding := samlAttr(child, "Binding")
		if binding != samlIDPHTTPRedirectBinding && binding != httpPostBinding {
			continue
		}
		location, response, ok := approvedIDPLogoutEndpoint(child, allowed)
		if !ok {
			return "", "", ErrInvalidInput
		}
		switch binding {
		case samlIDPHTTPRedirectBinding:
			if redirect != "" {
				return "", "", ErrInvalidInput
			}
			redirect = strings.Clone(location)
		case httpPostBinding:
			if post != "" {
				return "", "", ErrInvalidInput
			}
			post = strings.Clone(response)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if redirect == "" || post == "" {
		return "", "", ErrInvalidInput
	}
	return redirect, post, nil
}

func approvedIDPLogoutEndpoint(endpoint *xdm.Node, allowed map[string]struct{}) (location, response string, ok bool) {
	if _, empty := samlElementChildren(endpoint, 0); !empty {
		return "", "", false
	}
	location = samlAttr(endpoint, "Location")
	if !validSAMLLogoutDestination(location, allowed) {
		return "", "", false
	}
	// Metadata §2.2.2 makes ResponseLocation an alternate destination for
	// responses only. An absent attribute means responses reuse Location.
	response = location
	if attr := endpoint.Attr("", "ResponseLocation"); attr != nil {
		response = attr.Value()
		if !validSAMLLogoutDestination(response, allowed) {
			return "", "", false
		}
	}
	return location, response, true
}

func validSAMLLogoutDestination(raw string, allowed map[string]struct{}) bool {
	endpoint, valid := samlHTTPSURL(raw, maximumEndpointBytes, true)
	if !valid || strings.HasSuffix(endpoint.Host, ":") || !validFixedRedirectQuery(endpoint.RawQuery) {
		return false
	}
	if port := endpoint.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return false
		}
	}
	_, approved := allowed[strings.ToLower(endpoint.Hostname())]
	return approved
}

func samlLogoutDestinationHosts(names []string) (map[string]struct{}, error) {
	if len(names) == 0 || len(names) > 64 {
		return nil, ErrInvalidInput
	}
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		if len(name) > 253 || !strings.Contains(name, ".") || !validSAMLLogoutDNSName(name) {
			return nil, ErrInvalidInput
		}
		canonical := strings.ToLower(name)
		if _, duplicate := allowed[canonical]; duplicate {
			return nil, ErrInvalidInput
		}
		allowed[canonical] = struct{}{}
	}
	return allowed, nil
}

func validSAMLLogoutDNSName(name string) bool {
	var terminal string
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !asciiLetter(c) && !asciiDigit(c) && c != '-' {
				return false
			}
		}
		terminal = strings.ToLower(label)
	}
	// The URL Standard's IPv4 parsing is selected by a numeric (including
	// hexadecimal) terminal label. The approved policy selects only DNS names.
	if digits, hex := strings.CutPrefix(terminal, "0x"); hex {
		return strings.ContainsFunc(digits, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') })
	}
	return strings.ContainsFunc(terminal, func(c rune) bool { return c < '0' || c > '9' })
}
