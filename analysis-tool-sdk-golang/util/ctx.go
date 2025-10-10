package util

import (
	"context"
	"time"
)

type ctxKey string

const ctxKeyMetrics ctxKey = "metrics"

// NewRootContext 创建根context
func NewRootContext() (context.Context, context.CancelFunc) {
	metrics := make(map[string]any)
	return context.WithCancel(context.WithValue(context.Background(), ctxKeyMetrics, metrics))
}

// NewTimeoutContext 创建超时context
func NewTimeoutContext(ctx context.Context, maxTime time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, maxTime)
}

// Metrics 从 context 读取 metrics
func Metrics(ctx context.Context) map[string]any {
	return ctx.Value(ctxKeyMetrics).(map[string]any)
}

// RecordMetrics 记录metrics
func RecordMetrics(ctx context.Context, key string, value any) {
	Metrics(ctx)[key] = value
}

// StartTimer 启动一个计时器，返回停止函数，停止后将耗时写入metrics
// 使用方式：
//
//	stop := util.StartTimer(ctx, "executeTime")
//	defer stop()
func StartTimer(ctx context.Context, key string) func() {
	start := time.Now()
	return func() {
		RecordMetrics(ctx, key, time.Since(start).Milliseconds())
	}
}
