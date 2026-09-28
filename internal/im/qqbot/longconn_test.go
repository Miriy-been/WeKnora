package qqbot

import (
	"testing"
	"time"
)

// TestKeepaliveFor pins the watchdog deadline derivation: two missed heartbeat
// cycles announced by the gateway, floored at minKeepaliveTimeout so an
// aggressive interval cannot make us flap faster than the floor allows.
func TestKeepaliveFor(t *testing.T) {
	tests := []struct {
		name      string
		interval  time.Duration
		want      time.Duration
	}{
		{"zero interval clamps to floor", 0, minKeepaliveTimeout},
		{"default 45s → floor (2×45s == 90s)", 45 * time.Second, minKeepaliveTimeout},
		{"slow 60s gateway → 120s", 60 * time.Second, 120 * time.Second},
		{"aggressive 10s → floor", 10 * time.Second, minKeepaliveTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keepaliveFor(tt.interval); got != tt.want {
				t.Errorf("keepaliveFor(%v) = %v, want %v", tt.interval, got, tt.want)
			}
		})
	}
}

// TestReconnectDelayOverflow guards against the bug where large or negative
// attempt counters produced a non-positive duration, bypassing the max-delay
// cap and causing a busy reconnect loop — the same regression the WeCom
// client's test pins.
func TestReconnectDelayOverflow(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{"zero attempt clamps to base", 0, time.Second},
		{"negative attempt clamps to base", -5, time.Second},
		{"attempt 1 = base", 1, time.Second},
		{"attempt 2 = 2s", 2, 2 * time.Second},
		{"attempt 30 caps at max", 30, 30 * time.Second},
		{"attempt 100 caps at max", 100, 30 * time.Second},
		{"attempt overflowing seconds caps at max", 1 << 62, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reconnectDelay(tt.attempt)
			if got != tt.want {
				t.Errorf("reconnectDelay(%d) = %v, want %v", tt.attempt, got, tt.want)
			}
			if got <= 0 {
				t.Errorf("reconnectDelay(%d) returned non-positive %v — would cause busy loop", tt.attempt, got)
			}
		})
	}
}

// TestKeepaliveArmedAtConstruction pins the invariant the watchdog relies on:
// a fresh client starts with the floor deadline, so even the connect window
// before hello cannot hang forever.
func TestKeepaliveArmedAtConstruction(t *testing.T) {
	c := NewLongConnClient(nil, nil)
	if got := time.Duration(c.keepalive.Load()); got != minKeepaliveTimeout {
		t.Errorf("fresh client keepalive = %v, want %v", got, minKeepaliveTimeout)
	}
}
