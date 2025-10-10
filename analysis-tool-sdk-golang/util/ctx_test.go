package util

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	ctx, _ := NewRootContext()
	stop := StartTimer(ctx, "testTime")
	time.Sleep(2 * time.Second)
	stop()
	if metrics, err := json.Marshal(Metrics(ctx)); err == nil {
		Info(string(metrics))
	}
}
