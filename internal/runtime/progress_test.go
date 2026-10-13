package runtime

import (
	"testing"
	"time"
)

func TestProgressDeadline(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 10 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			r := &Runner{Interval: interval}
			now := time.Now()
			if r.Progressing(now) {
				t.Fatal("runtime without completed maintenance is healthy")
			}
			r.markProgress(now)
			deadline := max(3*interval, 15*time.Second)
			if !r.Progressing(now.Add(deadline - time.Nanosecond)) {
				t.Fatal("progress expired before its deadline")
			}
			if r.Progressing(now.Add(deadline)) {
				t.Fatal("stalled runtime remains healthy at its deadline")
			}
			r.markProgress(now.Add(deadline))
			if !r.Progressing(now.Add(deadline)) {
				t.Fatal("successful maintenance did not restore health")
			}
		})
	}
}

func TestProgressPreservesMonotonicClock(t *testing.T) {
	r := &Runner{}
	now := time.Now()
	r.markProgress(now)
	stored := *r.progress.Load()
	if stored != now || stored == stored.Round(0) {
		t.Fatal("progress lost its monotonic clock reading")
	}
}
