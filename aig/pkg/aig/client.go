package aig

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ClientOptions 用于在创建 Client 时覆盖默认配置。
//
// 大部分字段为可选（零值会回退到 Default* 常量）；唯一例外是 BaseURL，
// 必填且无默认值兜底——见下方字段注释。
type ClientOptions struct {
	// BaseURL 是 AIG 服务的接入地址。**必填**，由调用方明确传入；
	// 末尾斜杠会在 NewClientWithOptions 中被裁掉，调用方不必关心。
	BaseURL string

	// UploadTimeout 控制单次上传请求的整体超时（含网络与等待响应）。
	UploadTimeout time.Duration

	// PollInterval 控制轮询查询接口之间的等待间隔。
	PollInterval time.Duration

	// PollTimeout 控制整个轮询过程的最大等待时间。
	PollTimeout time.Duration

	// MaxRetries 控制单次查询出现网络错误时的最大重试次数。
	MaxRetries int

	// Model 是 mcp_scan 任务必须的 LLM 配置。
	Model ModelConfig

	// Prompt 是 mcp_scan 任务的扫描提示词描述（可选）。
	Prompt string

	// Language 控制 AIG 输出语言（zh/en），可选；为空时使用 DefaultLanguage。
	Language string

	// Thread 控制 AIG 后端的并发线程数；<=0 时使用 DefaultThread。
	Thread int
}

// NewClient 使用最简配置创建一个 AIG 客户端，所有可选字段都走默认值。
//
// **仅供单测/内部脚手架使用**：BaseURL 与 Model 都不会被填充，直接拿来
// 调用 server 一定会失败。生产路径应当走 NewClientWithOptions（并由
// 调用方保证 BaseURL 非空），单测可在拿到客户端后再手工 set BaseURL /
// HTTPClient（参考 newTestClient）。
func NewClient() *Client {
	return NewClientWithOptions(ClientOptions{})
}

// NewClientWithOptions 使用给定的配置创建 AIG 客户端。
//
// 行为约定：
//   - BaseURL **必填**，本构造器不做默认值兜底；如果调用方传入空字符串，
//     这里会原样保留为 ""，让 executor 层的早期校验或后续的 HTTP 请求
//     立刻报错（构造器保持薄、不返回 error，避免改函数签名带来的连锁修改）。
//   - 末尾斜杠会被裁掉，方便 url 拼接。
//   - 其余字段为零值时回退到对应的 Default* 常量。
func NewClientWithOptions(opts ClientOptions) *Client {
	baseURL := strings.TrimRight(opts.BaseURL, "/")

	uploadTimeout := opts.UploadTimeout
	if uploadTimeout <= 0 {
		uploadTimeout = DefaultUploadTimeout
	}

	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	pollTimeout := opts.PollTimeout
	if pollTimeout <= 0 {
		pollTimeout = DefaultPollTimeout
	}

	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}

	language := opts.Language
	if language == "" {
		language = DefaultLanguage
	}

	thread := opts.Thread
	if thread <= 0 {
		thread = DefaultThread
	}

	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: uploadTimeout,
		},
		PollInterval: pollInterval,
		PollTimeout:  pollTimeout,
		MaxRetries:   maxRetries,
		Model:        opts.Model,
		Prompt:       opts.Prompt,
		Language:     language,
		Thread:       thread,
	}
}

// decodeEnvelope 解析 AIG 标准 Envelope 响应，并校验 status==0。
//
// 当 HTTP 状态码非 2xx 时，会优先尝试从 body 中解析 Envelope 取出 message；
// 当 status!=0 时，把 message 包装为 error；
// 当一切正常时，把 data 反序列化到 out。
func decodeEnvelope(httpStatus int, body []byte, action string, out any) error {
	bodyStr := strings.TrimSpace(string(body))

	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		// HTTP 错误且无法解析为 Envelope，把原始 body 一起报出。
		if httpStatus < 200 || httpStatus >= 300 {
			return fmt.Errorf("%s failed: http=%d, body=%s", action, httpStatus, bodyStr)
		}
		return fmt.Errorf("%s decode response failed: %w, raw=%s", action, err, bodyStr)
	}

	if httpStatus < 200 || httpStatus >= 300 {
		msg := env.Message
		if msg == "" {
			msg = bodyStr
		}
		return fmt.Errorf("%s failed: http=%d, status=%d, message=%s", action, httpStatus, env.Status, msg)
	}

	if env.Status != EnvelopeStatusOK {
		return fmt.Errorf("%s failed: status=%d, message=%s", action, env.Status, env.Message)
	}

	if out == nil {
		return nil
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return fmt.Errorf("%s failed: empty data field, message=%s", action, env.Message)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("%s decode data failed: %w, raw=%s", action, err, string(env.Data))
	}
	return nil
}
