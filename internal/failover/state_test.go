package failover

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errProbe = errors.New("probe failed")

// fakeClock is a manually-advanced Clock for deterministic tests.
type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock               { return &fakeClock{now: time.Unix(0, 0)} }
func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// fakeActions is a scriptable Actions implementation: tests mutate
// liveErr/isolatedErr directly between Tick calls to script a scenario,
// with no real process or network involved.
type fakeActions struct {
	liveErr     error
	isolatedErr error

	switchCalls   []Role
	startPretestN int
	stopPretestN  int
}

func (f *fakeActions) ProbeLive(context.Context) error     { return f.liveErr }
func (f *fakeActions) ProbeIsolated(context.Context) error { return f.isolatedErr }

func (f *fakeActions) SwitchLiveTo(_ context.Context, role Role) error {
	f.switchCalls = append(f.switchCalls, role)
	return nil
}

func (f *fakeActions) StartIsolatedPretest(context.Context) error {
	f.startPretestN++
	return nil
}

func (f *fakeActions) StopIsolatedPretest(context.Context) error {
	f.stopPretestN++
	return nil
}

func testConfig() Config {
	return Config{
		FailuresRequired:          3,
		RecoverySuccessesRequired: 3,
		CooldownCycles:            2,
		RollbackBackoffSeconds:    300,
	}
}

func assertState(t *testing.T, m *Machine, want State) {
	t.Helper()
	if got := m.State(); got != want {
		t.Fatalf("state = %v, want %v", got, want)
	}
}

func TestMachine_StaysActivePrimaryWhileHealthy(t *testing.T) {
	actions := &fakeActions{}
	m := NewMachine(testConfig(), actions, newFakeClock(), StateActivePrimary)

	for i := 0; i < 5; i++ {
		m.Tick(context.Background())
		assertState(t, m, StateActivePrimary)
	}
	if len(actions.switchCalls) != 0 {
		t.Errorf("switchCalls = %v, want none", actions.switchCalls)
	}
}

func TestMachine_NormalFailoverAndRecovery(t *testing.T) {
	actions := &fakeActions{}
	clock := newFakeClock()
	m := NewMachine(testConfig(), actions, clock, StateActivePrimary)
	ctx := context.Background()

	// Primary fails 3 times in a row -> switch to backup + start isolated
	// pretest, enter cooldown. First two failures alone must not switch.
	actions.liveErr = errProbe
	m.Tick(ctx)
	assertState(t, m, StateActivePrimary)
	m.Tick(ctx)
	assertState(t, m, StateActivePrimary)
	m.Tick(ctx)
	assertState(t, m, StateCooldown)

	if len(actions.switchCalls) != 1 || actions.switchCalls[0] != RoleBackup {
		t.Fatalf("switchCalls = %v, want [RoleBackup]", actions.switchCalls)
	}
	if actions.startPretestN != 1 {
		t.Fatalf("startPretestN = %d, want 1", actions.startPretestN)
	}

	// Cooldown lasts exactly CooldownCycles ticks.
	m.Tick(ctx)
	assertState(t, m, StateCooldown)
	m.Tick(ctx)
	assertState(t, m, StateTestingRecovery)

	// Isolated recovery test succeeds 3 times -> switch back to primary,
	// then confirm over the next tick -> cooldown -> ActivePrimary.
	actions.isolatedErr = nil
	actions.liveErr = nil
	m.Tick(ctx)
	assertState(t, m, StateTestingRecovery)
	m.Tick(ctx)
	assertState(t, m, StateTestingRecovery)
	m.Tick(ctx) // 3rd isolated success -> switch to primary, start confirming
	assertState(t, m, StateConfirmingRecovery)

	if len(actions.switchCalls) != 2 || actions.switchCalls[1] != RolePrimary {
		t.Fatalf("switchCalls = %v, want [RoleBackup, RolePrimary]", actions.switchCalls)
	}
	if actions.stopPretestN != 1 {
		t.Fatalf("stopPretestN = %d, want 1", actions.stopPretestN)
	}

	m.Tick(ctx) // confirmation probe succeeds -> cooldown
	assertState(t, m, StateCooldown)
	m.Tick(ctx)
	assertState(t, m, StateCooldown)
	m.Tick(ctx)
	assertState(t, m, StateActivePrimary)
}

func TestMachine_FlapResistance_IsolatedFailureResetsCounter(t *testing.T) {
	actions := &fakeActions{}
	m := NewMachine(testConfig(), actions, newFakeClock(), StateTestingRecovery)
	ctx := context.Background()

	actions.isolatedErr = nil
	m.Tick(ctx) // success 1
	m.Tick(ctx) // success 2
	actions.isolatedErr = errProbe
	m.Tick(ctx) // failure -> resets the counter
	actions.isolatedErr = nil
	m.Tick(ctx) // success 1 (again)
	m.Tick(ctx) // success 2 (again)

	if len(actions.switchCalls) != 0 {
		t.Fatalf("switchCalls = %v, want none -- the failure should have reset the streak", actions.switchCalls)
	}
	assertState(t, m, StateTestingRecovery)

	m.Tick(ctx) // success 3 -> now switches
	if len(actions.switchCalls) != 1 {
		t.Fatalf("switchCalls = %v, want exactly 1 switch after 3 consecutive successes", actions.switchCalls)
	}
}

func TestMachine_FlapResistance_LiveFailureResetsCounter(t *testing.T) {
	actions := &fakeActions{}
	m := NewMachine(testConfig(), actions, newFakeClock(), StateActivePrimary)
	ctx := context.Background()

	actions.liveErr = errProbe
	m.Tick(ctx) // failure 1
	m.Tick(ctx) // failure 2
	actions.liveErr = nil
	m.Tick(ctx) // success -> resets
	actions.liveErr = errProbe
	m.Tick(ctx) // failure 1 (again)
	m.Tick(ctx) // failure 2 (again)

	if len(actions.switchCalls) != 0 {
		t.Fatalf("switchCalls = %v, want none -- the intervening success should have reset the streak", actions.switchCalls)
	}

	m.Tick(ctx) // failure 3 -> now switches
	if len(actions.switchCalls) != 1 {
		t.Fatalf("switchCalls = %v, want exactly 1 switch", actions.switchCalls)
	}
}

func TestMachine_RollbackOnFailedRecoveryConfirmation(t *testing.T) {
	actions := &fakeActions{}
	clock := newFakeClock()
	cfg := testConfig()
	m := NewMachine(cfg, actions, clock, StateTestingRecovery)
	ctx := context.Background()

	actions.isolatedErr = nil
	actions.liveErr = errProbe // the post-switch confirmation will keep failing
	m.Tick(ctx)
	m.Tick(ctx)
	m.Tick(ctx) // 3rd isolated success -> switch to primary, start confirming
	assertState(t, m, StateConfirmingRecovery)

	// Confirmation must fail FailuresRequired times in a row before rollback
	// -- a freshly restarted xray gets a few ticks to come up.
	m.Tick(ctx)
	assertState(t, m, StateConfirmingRecovery)
	m.Tick(ctx)
	assertState(t, m, StateConfirmingRecovery)
	m.Tick(ctx) // 3rd confirm failure -> rollback

	assertState(t, m, StateActiveBackup)
	if len(actions.switchCalls) != 2 {
		t.Fatalf("switchCalls = %v, want 2 (switch to primary, then rollback to backup)", actions.switchCalls)
	}
	if actions.switchCalls[0] != RolePrimary || actions.switchCalls[1] != RoleBackup {
		t.Fatalf("switchCalls = %v, want [RolePrimary, RoleBackup]", actions.switchCalls)
	}

	// Still within the rollback backoff -- must not retry yet even though
	// the isolated probe would now succeed.
	actions.isolatedErr = nil
	m.Tick(ctx)
	assertState(t, m, StateActiveBackup)

	// Advance the clock exactly past the backoff -> resumes recovery testing.
	clock.Advance(time.Duration(cfg.RollbackBackoffSeconds) * time.Second)
	m.Tick(ctx)
	assertState(t, m, StateTestingRecovery)
}

// TestMachine_ConfirmingRecovery_ToleratesStartupProbeFailures is the
// regression test for the recovery flap: a single live-probe failure
// right after the recovery switch (xray still starting) must NOT roll
// back. Only FailuresRequired in a row does.
func TestMachine_ConfirmingRecovery_ToleratesStartupProbeFailures(t *testing.T) {
	actions := &fakeActions{}
	m := NewMachine(testConfig(), actions, newFakeClock(), StateTestingRecovery)
	ctx := context.Background()

	actions.isolatedErr = nil
	m.Tick(ctx)
	m.Tick(ctx)
	m.Tick(ctx) // switch to primary -> CONFIRMING_RECOVERY
	assertState(t, m, StateConfirmingRecovery)

	// Two failed confirm probes (xray warming up), then it comes good.
	actions.liveErr = errProbe
	m.Tick(ctx)
	assertState(t, m, StateConfirmingRecovery)
	m.Tick(ctx)
	assertState(t, m, StateConfirmingRecovery)
	actions.liveErr = nil
	m.Tick(ctx) // confirm succeeds -> cooldown, no rollback
	assertState(t, m, StateCooldown)

	if len(actions.switchCalls) != 1 || actions.switchCalls[0] != RolePrimary {
		t.Fatalf("switchCalls = %v, want a single switch to primary (no rollback)", actions.switchCalls)
	}
}

func TestMachine_ZeroCooldownSkipsImmediately(t *testing.T) {
	actions := &fakeActions{}
	cfg := testConfig()
	cfg.CooldownCycles = 0
	m := NewMachine(cfg, actions, newFakeClock(), StateActivePrimary)
	ctx := context.Background()

	actions.liveErr = errProbe
	m.Tick(ctx)
	m.Tick(ctx)
	m.Tick(ctx) // 3rd failure -> switch, cooldown of 0 ticks -> straight through

	assertState(t, m, StateTestingRecovery)
}

func TestState_String(t *testing.T) {
	cases := map[State]string{
		StateActivePrimary:      "ACTIVE_PRIMARY",
		StateActiveBackup:       "ACTIVE_BACKUP",
		StateTestingRecovery:    "TESTING_RECOVERY",
		StateCooldown:           "COOLDOWN",
		StateConfirmingRecovery: "CONFIRMING_RECOVERY",
		State(99):               "UNKNOWN",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", state, got, want)
		}
	}
}

func TestRole_String(t *testing.T) {
	if RolePrimary.String() != "primary" {
		t.Errorf("RolePrimary.String() = %q, want \"primary\"", RolePrimary.String())
	}
	if RoleBackup.String() != "backup" {
		t.Errorf("RoleBackup.String() = %q, want \"backup\"", RoleBackup.String())
	}
}
