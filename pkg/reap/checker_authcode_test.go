package reap_test

import (
	"context"
	"testing"
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/reap"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	testclock "k8s.io/apimachinery/pkg/util/clock"
)

func TestAuthCodeChecker(t *testing.T) {
	clk := testclock.NewFakeClock(time.Now())

	tests := []struct {
		Name              string
		ConfigTuningEntry persistence.ConfigTuningEntry
		AuthCodeEntry     *persistence.AuthCodeEntry
		Step              time.Duration
		ExpectedError     string
	}{
		{
			Name:              "Non-refreshable, valid without expiry",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds) * time.Second,
		},
		{
			Name:              "Non-refreshable, valid with expiry",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(72 * time.Hour),
					},
				},
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds) * time.Second,
		},
		{
			Name:              "Non-refreshable, expired, but not yet reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds) * time.Second / 2,
		},
		{
			Name:              "Non-refreshable, expired, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds) * time.Second,
			ExpectedError: "token expired",
		},
		{
			Name: "Non-refreshable, expired, and non-refreshable reap criterion disabled",
			ConfigTuningEntry: persistence.ConfigTuningEntry{
				ReapNonRefreshableSeconds:  0,
				ReapRevokedSeconds:         persistence.DefaultConfigTuningEntry.ReapRevokedSeconds,
				ReapTransientErrorAttempts: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				ReapTransientErrorSeconds:  persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds,
			},
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds) * time.Second,
		},
		{
			Name:              "User error, valid without expiry, but time since last attempted issue not yet elapsed",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second / 2,
		},
		{
			Name:              "User error, valid without expiry, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second,
			ExpectedError: "token revoked: uh oh",
		},
		{
			Name:              "User error, valid with expiry",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(72 * time.Hour),
					},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second,
		},
		{
			Name:              "User error, expired, but not yet reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(10 * time.Second),
					},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second,
		},
		{
			Name:              "User error, expired, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(10 * time.Second),
					},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds)*time.Second + 10*time.Second,
			ExpectedError: "token revoked: uh oh",
		},
		{
			Name: "User error, expired, and revoked reap criterion disabled",
			ConfigTuningEntry: persistence.ConfigTuningEntry{
				ReapNonRefreshableSeconds:  persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds,
				ReapRevokedSeconds:         0,
				ReapTransientErrorAttempts: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				ReapTransientErrorSeconds:  persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds,
			},
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second,
		},
		{
			Name:              "User error, never issued, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				UserError:              "uh oh",
				LastAttemptedIssueTime: clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapRevokedSeconds) * time.Second,
			ExpectedError: "token revoked: uh oh",
		},
		{
			Name:              "Transient errors, valid without expiry, but time since last attempted issue not yet elapsed",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second / 2,
		},
		{
			Name:              "Transient errors, valid without expiry, but number of attempts not yet reached",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts / 2,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
		},
		{
			Name:              "Transient errors, valid without expiry, and both criteria apply",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{AccessToken: "test"},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
			ExpectedError: "transient errors exceeded limits, most recently: oh no",
		},
		{
			Name:              "Transient errors, valid with expiry",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(72 * time.Hour),
					},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
		},
		{
			Name:              "Transient errors, expired, but not yet reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(10 * time.Second),
					},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
		},
		{
			Name:              "Transient errors, expired, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now().Add(10 * time.Second),
					},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds)*time.Second + 10*time.Second,
			ExpectedError: "transient errors exceeded limits, most recently: oh no",
		},
		{
			Name: "Transient errors, expired, and transient attempts criterion disabled",
			ConfigTuningEntry: persistence.ConfigTuningEntry{
				ReapNonRefreshableSeconds:  persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds,
				ReapRevokedSeconds:         persistence.DefaultConfigTuningEntry.ReapRevokedSeconds,
				ReapTransientErrorAttempts: 0,
				ReapTransientErrorSeconds:  persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds,
			},
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
				TransientErrorsSinceLastIssue: 1,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
			ExpectedError: "transient errors exceeded limits, most recently: oh no",
		},
		{
			Name: "Transient errors, expired, and transient time-to-wait criterion disabled",
			ConfigTuningEntry: persistence.ConfigTuningEntry{
				ReapNonRefreshableSeconds:  persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds,
				ReapRevokedSeconds:         persistence.DefaultConfigTuningEntry.ReapRevokedSeconds,
				ReapTransientErrorAttempts: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				ReapTransientErrorSeconds:  0,
			},
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			ExpectedError: "transient errors exceeded limits, most recently: oh no",
		},
		{
			Name: "Transient errors, expired, but all transient criteria disabled",
			ConfigTuningEntry: persistence.ConfigTuningEntry{
				ReapNonRefreshableSeconds:  persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds,
				ReapRevokedSeconds:         persistence.DefaultConfigTuningEntry.ReapRevokedSeconds,
				ReapTransientErrorAttempts: 0,
				ReapTransientErrorSeconds:  0,
			},
			AuthCodeEntry: &persistence.AuthCodeEntry{
				Token: &provider.Token{
					Token: &oauth2.Token{
						AccessToken: "test",
						Expiry:      clk.Now(),
					},
				},
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step: time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
		},
		{
			Name:              "Transient errors, never issued, and reapable",
			ConfigTuningEntry: persistence.DefaultConfigTuningEntry,
			AuthCodeEntry: &persistence.AuthCodeEntry{
				TransientErrorsSinceLastIssue: persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
				LastTransientError:            "oh no",
				LastAttemptedIssueTime:        clk.Now(),
			},
			Step:          time.Duration(persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds) * time.Second,
			ExpectedError: "transient errors exceeded limits, most recently: oh no",
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			clk := k8sext.NewClock(testclock.NewFakeClock(clk.Now().Add(test.Step)))

			checker := reap.NewAuthCodeChecker(test.ConfigTuningEntry)
			err := checker.Check(clockctx.WithClock(context.Background(), clk), test.AuthCodeEntry)
			if test.ExpectedError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.ExpectedError)
			}
		})
	}
}
