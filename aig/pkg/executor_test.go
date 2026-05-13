package pkg

import (
	"context"
	"strings"
	"testing"
	"time"

	sdkObject "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
)

func TestBuildClientOptions_AllProvided(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyBaseURL, Value: "https://aig.test"},
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			{Type: "STRING", Key: ArgKeyModelBaseURL, Value: "https://api.openai.com/v1"},
			{Type: "STRING", Key: ArgKeyPrompt, Value: "scan it"},
			{Type: "STRING", Key: ArgKeyLanguage, Value: "en"},
			{Type: "NUMBER", Key: ArgKeyThread, Value: "8"},
			{Type: "NUMBER", Key: ArgKeyUploadTimeoutSeconds, Value: "60"},
			{Type: "NUMBER", Key: ArgKeyPollIntervalSeconds, Value: "3"},
			{Type: "NUMBER", Key: ArgKeyPollTimeoutSeconds, Value: "120"},
			{Type: "NUMBER", Key: ArgKeyMaxRetries, Value: "5"},
		},
	}
	opts := buildClientOptions(cfg)
	if opts.BaseURL != "https://aig.test" {
		t.Errorf("BaseURL = %q", opts.BaseURL)
	}
	if opts.Model.Model != "gpt-4" || opts.Model.Token != "sk-x" || opts.Model.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("Model = %+v", opts.Model)
	}
	if opts.Prompt != "scan it" {
		t.Errorf("Prompt = %q", opts.Prompt)
	}
	if opts.Language != "en" {
		t.Errorf("Language = %q", opts.Language)
	}
	if opts.Thread != 8 {
		t.Errorf("Thread = %d", opts.Thread)
	}
	if opts.UploadTimeout != 60*time.Second {
		t.Errorf("UploadTimeout = %s", opts.UploadTimeout)
	}
	if opts.PollInterval != 3*time.Second {
		t.Errorf("PollInterval = %s", opts.PollInterval)
	}
	if opts.PollTimeout != 120*time.Second {
		t.Errorf("PollTimeout = %s", opts.PollTimeout)
	}
	if opts.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d", opts.MaxRetries)
	}
}

func TestBuildClientOptions_MissingArgsFallbackToZero(t *testing.T) {
	cfg := &sdkObject.ToolConfig{}
	opts := buildClientOptions(cfg)
	if opts.BaseURL != "" || opts.UploadTimeout != 0 || opts.PollInterval != 0 ||
		opts.PollTimeout != 0 || opts.MaxRetries != 0 || opts.Thread != 0 ||
		opts.Language != "" || opts.Prompt != "" {
		t.Errorf("expected zero ClientOptions, got %+v", opts)
	}
	// 三个 Model 字段都不应该有任何默认值兜底（包括 BaseURL）。
	if opts.Model.Model != "" || opts.Model.Token != "" || opts.Model.BaseURL != "" {
		t.Errorf("expected empty Model, got %+v", opts.Model)
	}
}

// TestBuildClientOptions_ModelBaseURLNoDefault 显式锁定本次改动的契约：
// 当调用方没有传入 modelBaseUrl 时，buildClientOptions 不会塞默认值，
// opts.Model.BaseURL 严格保持空字符串，由 HasCredentials() 在调用 server 之前拦截。
func TestBuildClientOptions_ModelBaseURLNoDefault(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			// 故意不传 ArgKeyModelBaseURL
		},
	}
	opts := buildClientOptions(cfg)
	if opts.Model.BaseURL != "" {
		t.Errorf("expected Model.BaseURL to stay empty (no default fallback), got %q", opts.Model.BaseURL)
	}
}

// TestBuildClientOptions_AigBaseURLNoDefault 锁定 AIG 接入地址的"无默认值"契约：
// 调用方未传 baseUrl → opts.BaseURL 严格保留为空字符串，
// 由 Execute 入口的早期校验拦截（参考 TestExecute_RejectsMissingAigBaseUrl）。
func TestBuildClientOptions_AigBaseURLNoDefault(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			{Type: "STRING", Key: ArgKeyModelBaseURL, Value: "https://api"},
			// 故意不传 ArgKeyBaseURL
		},
	}
	opts := buildClientOptions(cfg)
	if opts.BaseURL != "" {
		t.Errorf("expected opts.BaseURL to stay empty (no default fallback), got %q", opts.BaseURL)
	}
}

// TestExecute_RejectsMissingAigBaseUrl 锁定 Execute 入口的早期校验：
// 当调用方提供了所有 model 凭据但漏配 baseUrl 时，Execute 应当立刻
// 返回 missing required tool argument "baseUrl"，不会触发任何上传/HTTP 调用。
func TestExecute_RejectsMissingAigBaseUrl(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			{Type: "STRING", Key: ArgKeyModelBaseURL, Value: "https://api"},
			// 故意不传 ArgKeyBaseURL
		},
	}
	// file 传 nil 没关系：baseUrl 校验在 file 校验之前。
	_, err := AigExecutor{}.Execute(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing baseUrl, got nil")
	}
	if !strings.Contains(err.Error(), `"`+ArgKeyBaseURL+`"`) {
		t.Errorf("expected error to mention %q arg key, got: %v", ArgKeyBaseURL, err)
	}
	if !strings.Contains(err.Error(), "missing required tool argument") {
		t.Errorf("expected canonical missing-arg phrasing, got: %v", err)
	}
}

// TestExecute_RejectsMissingModelBaseUrl 与上一条对称：保证此前的 modelBaseUrl
// 校验不会被 baseUrl 校验顺序的调整破坏。
func TestExecute_RejectsMissingModelBaseUrl(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "STRING", Key: ArgKeyModelName, Value: "gpt-4"},
			{Type: "STRING", Key: ArgKeyModelToken, Value: "sk-x"},
			{Type: "STRING", Key: ArgKeyBaseURL, Value: "https://aig.test"},
			// 故意不传 ArgKeyModelBaseURL
		},
	}
	_, err := AigExecutor{}.Execute(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing modelBaseUrl, got nil")
	}
	if !strings.Contains(err.Error(), `"`+ArgKeyModelBaseURL+`"`) {
		t.Errorf("expected error to mention %q arg key, got: %v", ArgKeyModelBaseURL, err)
	}
}

func TestBuildClientOptions_InvalidNumberIgnored(t *testing.T) {
	cfg := &sdkObject.ToolConfig{
		Args: []sdkObject.Argument{
			{Type: "NUMBER", Key: ArgKeyThread, Value: "abc"},
			{Type: "NUMBER", Key: ArgKeyUploadTimeoutSeconds, Value: "-1"},
			{Type: "NUMBER", Key: ArgKeyPollIntervalSeconds, Value: "0"},
			{Type: "NUMBER", Key: ArgKeyPollTimeoutSeconds, Value: "0"},
			{Type: "NUMBER", Key: ArgKeyMaxRetries, Value: "-2"},
		},
	}
	opts := buildClientOptions(cfg)
	if opts.Thread != 0 {
		t.Errorf("invalid number Thread should be ignored, got %d", opts.Thread)
	}
	if opts.UploadTimeout != 0 {
		t.Errorf("negative UploadTimeout should be ignored, got %s", opts.UploadTimeout)
	}
	if opts.PollInterval != 0 || opts.PollTimeout != 0 {
		t.Errorf("zero polls should be ignored, got %s/%s", opts.PollInterval, opts.PollTimeout)
	}
	if opts.MaxRetries != 0 {
		t.Errorf("negative MaxRetries should be ignored, got %d", opts.MaxRetries)
	}
}
