package config

import (
	"fmt"
	"strconv"
	"strings"
)

// failoverTunableKeys lists the FailoverConfig fields SetTunable accepts,
// in display order. Ports and the fallback-URL list aren't here: ports
// are wiring, not tuning, and a multi-value list doesn't fit a single
// "set <key> <value>" call.
var failoverTunableKeys = []string{
	"check_interval_seconds",
	"failures_required",
	"recovery_successes_required",
	"cooldown_cycles",
	"rollback_backoff_seconds",
	"check_retries",
	"check_retry_delay_seconds",
	"health_check_url",
}

// SetTunable adjusts one failover knob by its JSON field name, validating
// the value. Changing these only takes effect once the daemon restarts --
// its Machine reads Config once at construction, there is no live reload.
func (f *FailoverConfig) SetTunable(key, val string) error {
	switch key {
	case "check_interval_seconds":
		n, err := positiveInt(val)
		if err != nil {
			return fmt.Errorf("check_interval_seconds: %w", err)
		}
		f.CheckIntervalSeconds = n
	case "failures_required":
		n, err := positiveInt(val)
		if err != nil {
			return fmt.Errorf("failures_required: %w", err)
		}
		f.FailuresRequired = n
	case "recovery_successes_required":
		n, err := positiveInt(val)
		if err != nil {
			return fmt.Errorf("recovery_successes_required: %w", err)
		}
		f.RecoverySuccessesRequired = n
	case "cooldown_cycles":
		n, err := nonNegativeInt(val)
		if err != nil {
			return fmt.Errorf("cooldown_cycles: %w", err)
		}
		f.CooldownCycles = n
	case "rollback_backoff_seconds":
		n, err := nonNegativeInt(val)
		if err != nil {
			return fmt.Errorf("rollback_backoff_seconds: %w", err)
		}
		f.RollbackBackoffSeconds = n
	case "check_retries":
		n, err := nonNegativeInt(val)
		if err != nil {
			return fmt.Errorf("check_retries: %w", err)
		}
		f.CheckRetries = n
	case "check_retry_delay_seconds":
		n, err := nonNegativeInt(val)
		if err != nil {
			return fmt.Errorf("check_retry_delay_seconds: %w", err)
		}
		f.CheckRetryDelaySeconds = n
	case "health_check_url":
		if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
			return fmt.Errorf("health_check_url must start with http:// or https://")
		}
		f.HealthCheckURL = val
	default:
		return fmt.Errorf("unknown key %q (want one of: %s)", key, strings.Join(failoverTunableKeys, ", "))
	}
	return nil
}

// TunablesText renders the current failover knobs, one per line --
// SetTunable's keys plus the read-only fallback URL list.
func (f FailoverConfig) TunablesText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "check_interval_seconds: %d\n", f.CheckIntervalSeconds)
	fmt.Fprintf(&b, "failures_required: %d\n", f.FailuresRequired)
	fmt.Fprintf(&b, "recovery_successes_required: %d\n", f.RecoverySuccessesRequired)
	fmt.Fprintf(&b, "cooldown_cycles: %d\n", f.CooldownCycles)
	fmt.Fprintf(&b, "rollback_backoff_seconds: %d\n", f.RollbackBackoffSeconds)
	fmt.Fprintf(&b, "check_retries: %d\n", f.CheckRetries)
	fmt.Fprintf(&b, "check_retry_delay_seconds: %d\n", f.CheckRetryDelaySeconds)
	fmt.Fprintf(&b, "health_check_url: %s", f.HealthCheckURL)
	if len(f.HealthCheckFallbackURLs) > 0 {
		fmt.Fprintf(&b, "\nhealth_check_fallback_urls: %s", strings.Join(f.HealthCheckFallbackURLs, ", "))
	}
	return b.String()
}

func positiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("must be a positive integer, got %q", s)
	}
	return n, nil
}

func nonNegativeInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer, got %q", s)
	}
	return n, nil
}
