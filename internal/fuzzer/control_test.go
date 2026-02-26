package fuzzer

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestJobController_InitialStatus(t *testing.T) {
	ctrl := NewJobController(func() {})
	if got := ctrl.Status(); got != StatusRunning {
		t.Errorf("initial status = %q, want %q", got, StatusRunning)
	}
}

func TestJobController_PauseResume(t *testing.T) {
	ctrl := NewJobController(func() {})

	if err := ctrl.Pause(); err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	if got := ctrl.Status(); got != StatusPaused {
		t.Errorf("after Pause(), status = %q, want %q", got, StatusPaused)
	}

	if err := ctrl.Resume(); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if got := ctrl.Status(); got != StatusRunning {
		t.Errorf("after Resume(), status = %q, want %q", got, StatusRunning)
	}
}

func TestJobController_Pause_WhenNotRunning(t *testing.T) {
	ctrl := NewJobController(func() {})
	_ = ctrl.Pause()

	// Pausing again should fail.
	if err := ctrl.Pause(); err == nil {
		t.Error("expected error when pausing already-paused job")
	}
}

func TestJobController_Resume_WhenNotPaused(t *testing.T) {
	ctrl := NewJobController(func() {})
	if err := ctrl.Resume(); err == nil {
		t.Error("expected error when resuming a running job")
	}
}

func TestJobController_Cancel_FromRunning(t *testing.T) {
	cancelled := false
	ctrl := NewJobController(func() { cancelled = true })

	if err := ctrl.Cancel(); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if got := ctrl.Status(); got != StatusCancelled {
		t.Errorf("after Cancel(), status = %q, want %q", got, StatusCancelled)
	}
	if !cancelled {
		t.Error("cancel function was not called")
	}
}

func TestJobController_Cancel_FromPaused(t *testing.T) {
	cancelled := false
	ctrl := NewJobController(func() { cancelled = true })

	_ = ctrl.Pause()
	if err := ctrl.Cancel(); err != nil {
		t.Fatalf("Cancel() from paused error = %v", err)
	}
	if got := ctrl.Status(); got != StatusCancelled {
		t.Errorf("after Cancel(), status = %q, want %q", got, StatusCancelled)
	}
	if !cancelled {
		t.Error("cancel function was not called")
	}
}

func TestJobController_Cancel_WhenCompleted(t *testing.T) {
	ctrl := NewJobController(func() {})
	ctrl.Complete()

	if err := ctrl.Cancel(); err == nil {
		t.Error("expected error when cancelling completed job")
	}
}

func TestJobController_Stop(t *testing.T) {
	ctrl := NewJobController(func() {})
	ctrl.Stop(StatusError, "overload detected")

	if got := ctrl.Status(); got != StatusError {
		t.Errorf("after Stop(), status = %q, want %q", got, StatusError)
	}
	if got := ctrl.StopReason(); got != "overload detected" {
		t.Errorf("StopReason() = %q, want %q", got, "overload detected")
	}
}

func TestJobController_Stop_WhenTerminal(t *testing.T) {
	ctrl := NewJobController(func() {})
	ctrl.Complete()

	// Stop on already-terminal job should be a no-op.
	ctrl.Stop(StatusError, "should not apply")
	if got := ctrl.Status(); got != StatusCompleted {
		t.Errorf("status after Stop on completed = %q, want %q", got, StatusCompleted)
	}
}

func TestJobController_Complete(t *testing.T) {
	ctrl := NewJobController(func() {})
	ctrl.Complete()

	if got := ctrl.Status(); got != StatusCompleted {
		t.Errorf("after Complete(), status = %q, want %q", got, StatusCompleted)
	}
}

func TestJobController_Complete_WhenNotRunning(t *testing.T) {
	ctrl := NewJobController(func() {})
	_ = ctrl.Pause()

	ctrl.Complete()
	// Should remain paused since Complete only works from running.
	if got := ctrl.Status(); got != StatusPaused {
		t.Errorf("status = %q, want %q", got, StatusPaused)
	}
}

func TestJobController_WaitIfPaused_NotPaused(t *testing.T) {
	ctrl := NewJobController(func() {})

	err := ctrl.WaitIfPaused(context.Background())
	if err != nil {
		t.Fatalf("WaitIfPaused() on running job = %v, want nil", err)
	}
}

func TestJobController_WaitIfPaused_ResumeUnblocks(t *testing.T) {
	ctrl := NewJobController(func() {})
	_ = ctrl.Pause()

	done := make(chan error, 1)
	go func() {
		done <- ctrl.WaitIfPaused(context.Background())
	}()

	// Give the goroutine time to block.
	time.Sleep(10 * time.Millisecond)

	_ = ctrl.Resume()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitIfPaused() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitIfPaused() did not unblock after Resume()")
	}
}

func TestJobController_WaitIfPaused_CancelUnblocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctrl := NewJobController(func() {})
	_ = ctrl.Pause()

	done := make(chan error, 1)
	go func() {
		done <- ctrl.WaitIfPaused(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("WaitIfPaused() = nil, want context error")
		}
	case <-time.After(time.Second):
		t.Fatal("WaitIfPaused() did not unblock after context cancel")
	}
}

func TestJobController_WaitIfPaused_CancelFromPaused(t *testing.T) {
	ctrl := NewJobController(func() {})
	_ = ctrl.Pause()

	done := make(chan error, 1)
	go func() {
		done <- ctrl.WaitIfPaused(context.Background())
	}()

	time.Sleep(10 * time.Millisecond)
	_ = ctrl.Cancel()

	select {
	case err := <-done:
		// After Cancel, status is cancelled and WaitIfPaused should return nil
		// (status is no longer paused).
		if err != nil {
			t.Fatalf("WaitIfPaused() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitIfPaused() did not unblock after Cancel()")
	}
}

func TestJobRegistry_RegisterGetRemove(t *testing.T) {
	reg := NewJobRegistry()

	ctrl := NewJobController(func() {})
	reg.Register("job-1", ctrl)

	got := reg.Get("job-1")
	if got != ctrl {
		t.Error("Get() returned wrong controller")
	}

	if reg.Get("nonexistent") != nil {
		t.Error("Get() for nonexistent key should return nil")
	}

	reg.Remove("job-1")
	if reg.Get("job-1") != nil {
		t.Error("Get() after Remove() should return nil")
	}
}

func TestJobRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewJobRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "job-" + string(rune('0'+id%10))
			ctrl := NewJobController(func() {})
			reg.Register(key, ctrl)
			reg.Get(key)
			reg.Remove(key)
		}(i)
	}
	wg.Wait()
}
