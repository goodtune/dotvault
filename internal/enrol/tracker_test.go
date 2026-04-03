package enrol

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

func TestTracker_GetStatus_NotTracked(t *testing.T) {
	tracker := NewTracker()
	if s := tracker.GetStatus("nokey"); s != nil {
		t.Errorf("expected nil for untracked key, got %v", s)
	}
}

func TestTracker_Clear(t *testing.T) {
	tracker := NewTracker()
	tracker.mu.Lock()
	tracker.statuses["k"] = &EnrolmentStatus{State: StateFailed, Error: "oops"}
	tracker.mu.Unlock()

	tracker.Clear("k")

	if s := tracker.GetStatus("k"); s != nil {
		t.Errorf("expected nil after clear, got %v", s)
	}
}

func TestTracker_Start_Success(t *testing.T) {
	vc := testVC

	eng := &mockEngine{name: "test", fields: []string{"tok"}, creds: map[string]string{"tok": "abc"}}
	RegisterEngine("test-tracker", eng)
	t.Cleanup(func() { UnregisterEngine("test-tracker") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"mykey": {Engine: "test-tracker"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	tracker := NewTracker()
	ctx := context.Background()

	ok := tracker.Start(ctx, mgr, "mykey")
	if !ok {
		t.Fatal("Start returned false, want true")
	}

	// Wait for async completion.
	deadline := time.After(5 * time.Second)
	for {
		s := tracker.GetStatus("mykey")
		if s != nil && (s.State == StateComplete || s.State == StateFailed) {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for enrolment to complete")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestTracker_Start_AlreadyRunning(t *testing.T) {
	tracker := NewTracker()
	tracker.mu.Lock()
	tracker.statuses["k"] = &EnrolmentStatus{State: StateRunning}
	tracker.mu.Unlock()

	// Should return false because it's already running.
	ok := tracker.Start(context.Background(), nil, "k")
	if ok {
		t.Error("Start returned true for already-running enrolment")
	}
}

func TestTracker_Start_DeviceCode(t *testing.T) {
	vc := testVC

	// Engine that calls OnDeviceCode via IO.
	deviceEng := &deviceCodeEngine{
		name:   "device",
		fields: []string{"tok"},
		creds:  map[string]string{"tok": "abc"},
	}
	RegisterEngine("test-device", deviceEng)
	t.Cleanup(func() { UnregisterEngine("test-device") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"devkey": {Engine: "test-device"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	tracker := NewTracker()
	ctx := context.Background()

	tracker.Start(ctx, mgr, "devkey")

	// Wait for device code to appear.
	deadline := time.After(5 * time.Second)
	for {
		s := tracker.GetStatus("devkey")
		if s != nil && s.State == StateAwaitingUser {
			if s.DeviceCode == nil {
				t.Fatal("awaiting_user state but no device code")
			}
			if s.DeviceCode.UserCode != "ABCD-1234" {
				t.Errorf("user_code = %q, want %q", s.DeviceCode.UserCode, "ABCD-1234")
			}
			break
		}
		if s != nil && (s.State == StateComplete || s.State == StateFailed) {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for device code state")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// deviceCodeEngine calls OnDeviceCode during Run.
type deviceCodeEngine struct {
	name   string
	fields []string
	creds  map[string]string
}

func (e *deviceCodeEngine) Name() string     { return e.name }
func (e *deviceCodeEngine) Fields() []string { return e.fields }
func (e *deviceCodeEngine) Run(_ context.Context, _ map[string]any, io IO) (map[string]string, error) {
	if io.OnDeviceCode != nil {
		io.OnDeviceCode(DeviceCodeInfo{
			UserCode:        "ABCD-1234",
			VerificationURI: "https://example.com/device",
		})
	}
	return e.creds, nil
}
