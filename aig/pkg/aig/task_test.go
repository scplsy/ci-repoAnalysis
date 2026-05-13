package aig

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateMcpScanTask_Success(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/app/taskapi/tasks" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected json content-type, got %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode body failed: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"session_id":"sess-001"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	c.Prompt = "scan this server"
	resp, err := c.CreateMcpScanTask(context.Background(), "http://localhost/uploads/x.zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SessionID != "sess-001" {
		t.Errorf("SessionID = %q", resp.SessionID)
	}

	// 校验请求体结构与字段
	if captured["type"] != TaskTypeMcpScan {
		t.Errorf("type = %v", captured["type"])
	}
	content, ok := captured["content"].(map[string]any)
	if !ok {
		t.Fatalf("content not a map: %T", captured["content"])
	}
	if content["attachments"] != "http://localhost/uploads/x.zip" {
		t.Errorf("attachments = %v", content["attachments"])
	}
	if content["prompt"] != "scan this server" {
		t.Errorf("prompt = %v", content["prompt"])
	}
	if content["language"] != DefaultLanguage {
		t.Errorf("language = %v", content["language"])
	}
	if int(content["thread"].(float64)) != DefaultThread {
		t.Errorf("thread = %v", content["thread"])
	}
	model, ok := content["model"].(map[string]any)
	if !ok {
		t.Fatalf("model not a map: %T", content["model"])
	}
	if model["model"] != "gpt-4" || model["token"] != "sk-test" {
		t.Errorf("model = %+v", model)
	}
}

func TestCreateMcpScanTask_OmitsEmptyPrompt(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"session_id":"sess-2"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	c.Prompt = ""
	if _, err := c.CreateMcpScanTask(context.Background(), "http://localhost/x.zip"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	content := captured["content"].(map[string]any)
	if _, ok := content["prompt"]; ok {
		t.Errorf("expected prompt absent, got %v", content["prompt"])
	}
}

func TestCreateMcpScanTask_MissingModel(t *testing.T) {
	c := NewClient()
	_, err := c.CreateMcpScanTask(context.Background(), "http://localhost/x.zip")
	if !errors.Is(err, ErrMissingModelCredentials) {
		t.Errorf("expected ErrMissingModelCredentials, got %v", err)
	}
}

// TestCreateMcpScanTask_AnyMissingModelField 覆盖三个必填字段
// （model / token / base_url）任意一个缺失都应触发 ErrMissingModelCredentials。
// BaseURL 在本次改动后不再有"OpenAI 默认"的兜底，必须由调用方明确提供。
func TestCreateMcpScanTask_AnyMissingModelField(t *testing.T) {
	cases := []struct {
		name string
		m    ModelConfig
	}{
		{"missing model", ModelConfig{Token: "x", BaseURL: "x"}},
		{"missing token", ModelConfig{Model: "x", BaseURL: "x"}},
		{"missing base_url", ModelConfig{Model: "x", Token: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient()
			c.Model = tc.m
			_, err := c.CreateMcpScanTask(context.Background(), "http://localhost/x.zip")
			if !errors.Is(err, ErrMissingModelCredentials) {
				t.Errorf("expected ErrMissingModelCredentials, got %v", err)
			}
		})
	}
}

// TestCreateMcpScanTask_BaseURLAlwaysSerialized 校验：即使 BaseURL 为空也会
// 出现在请求体中（json tag 不带 omitempty），让 server 端给出明确错误。
// 这是为了和 HasCredentials 的客户端拦截形成"双保险"——万一调用方
// 直接构造 ModelConfig 绕过 Execute 的入参校验，server 也能察觉。
func TestCreateMcpScanTask_BaseURLAlwaysSerialized(t *testing.T) {
	body, err := json.Marshal(ModelConfig{Model: "m", Token: "t", BaseURL: ""})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(body), `"base_url":""`) {
		t.Errorf("expected base_url field to be serialized even when empty, got %s", body)
	}
}

func TestCreateMcpScanTask_MissingFileURL(t *testing.T) {
	c := newTestClient(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	_, err := c.CreateMcpScanTask(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty fileURL")
	}
	if !strings.Contains(err.Error(), "fileUrl") {
		t.Errorf("expected fileUrl in error, got %v", err)
	}
}

func TestCreateMcpScanTask_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":1,"message":"invalid attachments","data":null}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.CreateMcpScanTask(context.Background(), "http://localhost/x.zip")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid attachments") {
		t.Errorf("expected message in error, got %v", err)
	}
}

func TestCreateMcpScanTask_MissingSessionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.CreateMcpScanTask(context.Background(), "http://localhost/x.zip")
	if err == nil {
		t.Fatal("expected error for missing session_id")
	}
}
