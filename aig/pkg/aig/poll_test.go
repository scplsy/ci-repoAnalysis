package aig

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueryStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/app/taskapi/status/sess-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"session_id":"sess-1","status":"doing","title":"mcp scan","log":"abc"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	resp, err := c.QueryStatus(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if resp.Status != TaskStatusRunning || resp.SessionID != "sess-1" {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestQueryStatus_MissingStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"session_id":"sess-1"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.QueryStatus(context.Background(), "sess-1")
	if err == nil {
		t.Fatal("expected error for missing status field")
	}
}

func TestQueryResult_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/app/taskapi/result/sess-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{`+
				`"id":"abc","type":"resultUpdate","timestamp":1778571245,`+
				`"result":{`+
				`"start_time":1778570974.04,"end_time":1778571245.39,`+
				`"language":"Other","llm":"kimi-k2.5","readme":"## info","score":60,`+
				`"results":[{"title":"t1","level":"high","description":"d1","risk_type":"rt"}]`+
				`}}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	resp, err := c.QueryResult(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if resp.ID != "abc" || resp.Type != "resultUpdate" || resp.Timestamp != 1778571245 {
		t.Errorf("envelope meta wrong: %+v", resp)
	}
	if resp.Result.Score != 60 || resp.Result.LLM != "kimi-k2.5" || resp.Result.Language != "Other" {
		t.Errorf("scan meta wrong: %+v", resp.Result)
	}
	if resp.Result.Readme != "## info" {
		t.Errorf("readme wrong: %q", resp.Result.Readme)
	}
	if len(resp.Result.Results) != 1 || resp.Result.Results[0].Title != "t1" {
		t.Errorf("results = %+v", resp.Result.Results)
	}
}

func TestQueryResult_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"id":"x","type":"resultUpdate","result":{"score":100,"results":[]}}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	resp, err := c.QueryResult(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(resp.Result.Results) != 0 {
		t.Errorf("expected empty results, got %d", len(resp.Result.Results))
	}
	if resp.Result.Score != 100 {
		t.Errorf("expected score=100, got %d", resp.Result.Score)
	}
}

func TestWaitForResult_PollUntilCompleted(t *testing.T) {
	var statusCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/app/taskapi/status/"):
			n := atomic.AddInt32(&statusCalls, 1)
			w.WriteHeader(http.StatusOK)
			if n < 3 {
				_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"session_id":"h","status":"doing"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"session_id":"h","status":"done"}}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/app/taskapi/result/"):
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w,
				`{"status":0,"message":"ok","data":{"id":"x","type":"resultUpdate","result":{"score":80,"results":[{"title":"t1","level":"medium"}]}}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := newTestClient(server)
	resp, err := c.WaitForResult(context.Background(), "h")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(resp.Result.Results) != 1 {
		t.Errorf("results = %+v", resp.Result.Results)
	}
	if resp.Result.Score != 80 {
		t.Errorf("score = %d", resp.Result.Score)
	}
	if atomic.LoadInt32(&statusCalls) < 3 {
		t.Errorf("expected at least 3 status polls, got %d", statusCalls)
	}
}

func TestWaitForResult_FailedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"session_id":"h","status":"error","log":"engine crashed"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.WaitForResult(context.Background(), "h")
	if err == nil {
		t.Fatal("expected error for failed status")
	}
	if !strings.Contains(err.Error(), "engine crashed") {
		t.Errorf("expected log in error: %v", err)
	}
}

func TestWaitForResult_FailedNoLog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"session_id":"h","status":"error"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.WaitForResult(context.Background(), "h")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no log provided") {
		t.Errorf("expected fallback message, got %v", err)
	}
}

func TestWaitForResult_RetryThenExhaust(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"status":1,"message":"boom","data":null}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.WaitForResult(context.Background(), "h")
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	// MaxRetries=2 表示总共应该尝试 1 + 2 = 3 次
	if got := atomic.LoadInt32(&calls); got != int32(c.MaxRetries+1) {
		t.Errorf("expected %d attempts, got %d", c.MaxRetries+1, got)
	}
}

func TestWaitForResult_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"session_id":"h","status":"doing"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, err := c.WaitForResult(ctx, "h")
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if !errors.Is(err, context.Canceled) &&
		!strings.Contains(err.Error(), "canceled") &&
		!strings.Contains(err.Error(), "timeout") {
		t.Logf("got error: %v", err)
	}
}

func TestTruncateLog(t *testing.T) {
	cases := []struct {
		name  string
		log   string
		max   int
		want  string
		exact bool
	}{
		{"short", "hello", 100, "hello", true},
		{"max zero", "abcdef", 0, "abcdef", true},
		{"truncate", strings.Repeat("a", 100), 10, "aaaaaaaaaa...(truncated)", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := truncateLog(c.log, c.max)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
