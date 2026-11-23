package postgres

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSAMLReplayRetainsOriginalAssertionLifetime(t *testing.T) {
	validation := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		assertion time.Time
		want      time.Time
	}{
		{"ten-minute minimum", validation.Add(time.Minute), validation.Add(10 * time.Minute)},
		{"raw assertion expiry plus five minutes", validation.Add(30 * time.Minute), validation.Add(35 * time.Minute)},
		{"storage rounds up without shortening replay protection", validation.Add(30*time.Minute + time.Nanosecond), validation.Add(35*time.Minute + time.Microsecond)},
		{"exact upper bound", validation.Add(24*time.Hour - 5*time.Minute), validation.Add(24 * time.Hour)},
		{"invalid original assertion expiry", time.Time{}, time.Time{}},
		{"outside retention budget", validation.Add(24*time.Hour - 5*time.Minute + time.Nanosecond), time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retain, err := samlReplayRetainUntil(validation, tc.assertion)
			if tc.want.IsZero() {
				if err == nil || !retain.IsZero() {
					t.Fatal("invalid expiry yielded an admissible replay deadline")
				}
				return
			}
			if err != nil || !retain.Equal(tc.want) || retain.Location() != time.UTC {
				t.Fatal("did not retain the original assertion deadline", err)
			}
		})
	}
}

func TestSAMLReplayRejectsUnaffiliatedCoordinatorWork(t *testing.T) {
	if err := reserveSAMLReplayInWork(t.Context(), kernel.Work{}, nil, samlReplayClaim{}); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("unaffiliated Work reached replay mutation", err)
	}
}
