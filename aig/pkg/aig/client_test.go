package aig

import (
	"testing"
	"time"
)

func TestNewClientWithOptions_Defaults(t *testing.T) {
	c := NewClient()
	// BaseURL 没有默认值兜底：调用方未传入 → 严格保留为空字符串，
	// 让上游早一步在 executor 层拦截，避免 silent failure。
	if c.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty string (no default fallback)", c.BaseURL)
	}
	if c.HTTPClient.Timeout != DefaultUploadTimeout {
		t.Errorf("Timeout = %s, want %s", c.HTTPClient.Timeout, DefaultUploadTimeout)
	}
	if c.PollInterval != DefaultPollInterval {
		t.Errorf("PollInterval = %s", c.PollInterval)
	}
	if c.PollTimeout != DefaultPollTimeout {
		t.Errorf("PollTimeout = %s", c.PollTimeout)
	}
	if c.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d", c.MaxRetries)
	}
	if c.Language != DefaultLanguage {
		t.Errorf("Language = %q", c.Language)
	}
	if c.Thread != DefaultThread {
		t.Errorf("Thread = %d", c.Thread)
	}
}

func TestNewClientWithOptions_OverrideAll(t *testing.T) {
	c := NewClientWithOptions(ClientOptions{
		BaseURL:       "https://aig.example.com/",
		UploadTimeout: 90 * time.Second,
		PollInterval:  2 * time.Second,
		PollTimeout:   5 * time.Minute,
		MaxRetries:    7,
		Model:         ModelConfig{Model: "gpt-4", Token: "sk-x", BaseURL: "https://api.openai.com/v1"},
		Prompt:        "scan this",
		Language:      "en",
		Thread:        16,
	})
	// 末尾斜杠应被去掉
	if c.BaseURL != "https://aig.example.com" {
		t.Errorf("BaseURL = %q", c.BaseURL)
	}
	if c.HTTPClient.Timeout != 90*time.Second {
		t.Errorf("Timeout = %s", c.HTTPClient.Timeout)
	}
	if c.PollInterval != 2*time.Second {
		t.Errorf("PollInterval = %s", c.PollInterval)
	}
	if c.PollTimeout != 5*time.Minute {
		t.Errorf("PollTimeout = %s", c.PollTimeout)
	}
	if c.MaxRetries != 7 {
		t.Errorf("MaxRetries = %d", c.MaxRetries)
	}
	if c.Model.Model != "gpt-4" || c.Model.Token != "sk-x" {
		t.Errorf("Model = %+v", c.Model)
	}
	if c.Prompt != "scan this" {
		t.Errorf("Prompt = %q", c.Prompt)
	}
	if c.Language != "en" {
		t.Errorf("Language = %q", c.Language)
	}
	if c.Thread != 16 {
		t.Errorf("Thread = %d", c.Thread)
	}
}

func TestNewClientWithOptions_NegativeAndZeroFallback(t *testing.T) {
	c := NewClientWithOptions(ClientOptions{
		BaseURL:       "",
		UploadTimeout: -1 * time.Second,
		PollInterval:  0,
		PollTimeout:   -1,
		MaxRetries:    -3,
		Thread:        -2,
	})
	// BaseURL 不再有 default fallback；空字符串原样保留。
	if c.BaseURL != "" {
		t.Errorf("BaseURL should stay empty (no default fallback), got %q", c.BaseURL)
	}
	if c.HTTPClient.Timeout != DefaultUploadTimeout {
		t.Errorf("UploadTimeout fallback failed: %s", c.HTTPClient.Timeout)
	}
	if c.PollInterval != DefaultPollInterval {
		t.Errorf("PollInterval fallback failed: %s", c.PollInterval)
	}
	if c.PollTimeout != DefaultPollTimeout {
		t.Errorf("PollTimeout fallback failed: %s", c.PollTimeout)
	}
	if c.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries fallback failed: %d", c.MaxRetries)
	}
	if c.Thread != DefaultThread {
		t.Errorf("Thread fallback failed: %d", c.Thread)
	}
}

// TestNewClientWithOptions_TrimsTrailingSlash 锁定行为：构造器会去掉 BaseURL
// 末尾的斜杠，便于后续 url 拼接（c.BaseURL + "/api/..."）。
func TestNewClientWithOptions_TrimsTrailingSlash(t *testing.T) {
	cases := map[string]string{
		"https://aig.example.com/":      "https://aig.example.com",
		"https://aig.example.com":       "https://aig.example.com",
		"https://aig.example.com:8088/": "https://aig.example.com:8088",
		"http://localhost:8088///":      "http://localhost:8088",
		"":                              "", // 空仍然是空，不做任何兜底
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			c := NewClientWithOptions(ClientOptions{BaseURL: in})
			if c.BaseURL != want {
				t.Errorf("BaseURL = %q, want %q", c.BaseURL, want)
			}
		})
	}
}

func TestModelConfig_HasCredentials(t *testing.T) {
	// BaseURL 现在是必填字段（无默认值兜底），所以 HasCredentials 要求三者全非空。
	cases := []struct {
		name string
		m    ModelConfig
		want bool
	}{
		{"all three set", ModelConfig{Model: "gpt-4", Token: "sk", BaseURL: "https://api"}, true},
		{"missing base_url", ModelConfig{Model: "gpt-4", Token: "sk"}, false},
		{"missing token", ModelConfig{Model: "gpt-4", BaseURL: "https://api"}, false},
		{"missing model", ModelConfig{Token: "sk", BaseURL: "https://api"}, false},
		{"only model", ModelConfig{Model: "gpt-4"}, false},
		{"only token", ModelConfig{Token: "sk"}, false},
		{"only base_url", ModelConfig{BaseURL: "https://api"}, false},
		{"all empty", ModelConfig{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.m.HasCredentials(); got != c.want {
				t.Errorf("HasCredentials() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDecodeEnvelope_Success(t *testing.T) {
	body := []byte(`{"status":0,"message":"ok","data":{"fileUrl":"http://example/f.zip","filename":"f.zip","size":1024}}`)
	var data UploadData
	if err := decodeEnvelope(200, body, "test", &data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.FileURL != "http://example/f.zip" || data.Size != 1024 {
		t.Errorf("decoded = %+v", data)
	}
}

func TestDecodeEnvelope_StatusFail(t *testing.T) {
	body := []byte(`{"status":1,"message":"bad request","data":null}`)
	var data UploadData
	err := decodeEnvelope(200, body, "test", &data)
	if err == nil {
		t.Fatal("expected error for status=1")
	}
	if !contains(err.Error(), "bad request") {
		t.Errorf("expected message in error, got: %v", err)
	}
}

func TestDecodeEnvelope_HTTPError(t *testing.T) {
	body := []byte(`{"status":1,"message":"server boom","data":null}`)
	var data UploadData
	err := decodeEnvelope(500, body, "test", &data)
	if err == nil {
		t.Fatal("expected error for http=500")
	}
	if !contains(err.Error(), "server boom") || !contains(err.Error(), "500") {
		t.Errorf("expected http/message info, got: %v", err)
	}
}

func TestDecodeEnvelope_HTTPErrorNonJSON(t *testing.T) {
	body := []byte(`<html>boom</html>`)
	var data UploadData
	err := decodeEnvelope(502, body, "test", &data)
	if err == nil {
		t.Fatal("expected error for non-json error body")
	}
	if !contains(err.Error(), "502") {
		t.Errorf("expected http code in error, got: %v", err)
	}
}

func TestDecodeEnvelope_EmptyData(t *testing.T) {
	body := []byte(`{"status":0,"message":"ok","data":null}`)
	var data UploadData
	err := decodeEnvelope(200, body, "test", &data)
	if err == nil {
		t.Fatal("expected error for empty data with non-nil out")
	}
}

func TestDecodeEnvelope_NoOutAllowed(t *testing.T) {
	body := []byte(`{"status":0,"message":"ok","data":null}`)
	if err := decodeEnvelope(200, body, "test", nil); err != nil {
		t.Errorf("unexpected error when out=nil: %v", err)
	}
}

func TestResultData_DecodeRealEnvelope(t *testing.T) {
	// 真实抓包样本（节选）：data 直接是 resultUpdate 事件，结果在 data.result.results。
	body := []byte(`{"status":0,"message":"ok","data":{` +
		`"id":"911a2c06-5e33-4c68-8e33-f7452707b42d",` +
		`"type":"resultUpdate","timestamp":1778571245,` +
		`"result":{` +
		`"end_time":1778571245.3908386,"start_time":1778570974.0439188,` +
		`"language":"Other","llm":"kimi-k2.5","readme":"## info","score":60,` +
		`"results":[{"title":"t","level":"High","risk_type":"Intent Poisoning",` +
		`"description":"d","suggestion":"s"}]` +
		`}}}`)
	var data ResultData
	if err := decodeEnvelope(200, body, "test", &data); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if data.ID != "911a2c06-5e33-4c68-8e33-f7452707b42d" || data.Type != "resultUpdate" {
		t.Errorf("event meta wrong: %+v", data)
	}
	if data.Result.Score != 60 || data.Result.LLM != "kimi-k2.5" {
		t.Errorf("scan meta wrong: %+v", data.Result)
	}
	if data.Result.StartTime != 1778570974.0439188 || data.Result.EndTime != 1778571245.3908386 {
		t.Errorf("timestamps wrong: %+v", data.Result)
	}
	if len(data.Result.Results) != 1 || data.Result.Results[0].Level != "High" {
		t.Errorf("results wrong: %+v", data.Result.Results)
	}
}

// contains is a tiny helper to keep tests free of strings.Contains imports.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
