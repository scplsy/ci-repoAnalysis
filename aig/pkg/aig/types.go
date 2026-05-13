// Package aig 提供与 AI-Infra-Guard（https://github.com/Tencent/AI-Infra-Guard）
// 后端服务交互的 HTTP 客户端，覆盖文件上传、创建 mcp_scan 任务、查询任务状态
// 与拉取扫描结果的完整流程。
package aig

import (
	"encoding/json"
	"net/http"
	"time"
)

// AIG 接口路径与字段常量。
// 调用方必须在 ClientOptions.BaseURL 中明确传入完整 URL
const (
	uploadPath    = "/api/v1/app/taskapi/upload"
	taskPath      = "/api/v1/app/taskapi/tasks"
	statusPathFmt = "/api/v1/app/taskapi/status/%s"
	resultPathFmt = "/api/v1/app/taskapi/result/%s"

	// MultipartFieldFile 上传文件的 multipart 字段名。
	MultipartFieldFile = "file"

	// TaskTypeMcpScan mcp_scan 任务类型常量。
	TaskTypeMcpScan = "mcp_scan"
)

// AIG 通用响应中的 status 字段取值。
const (
	EnvelopeStatusOK   = 0 // 成功
	EnvelopeStatusFail = 1 // 失败
)

// AIG 任务状态枚举。
const (
	TaskStatusPending    = "todo"
	TaskStatusRunning    = "doing"
	TaskStatusCompleted  = "done"
	TaskStatusFailed     = "error"
	TaskStatusTerminated = "terminated"
)

// 默认超时与重试相关配置。
const (
	DefaultUploadTimeout = 5 * time.Minute
	DefaultQueryTimeout  = 30 * time.Second
	DefaultPollInterval  = 5 * time.Second
	DefaultPollTimeout   = 30 * time.Minute
	DefaultMaxRetries    = 3
	DefaultThread        = 4
	DefaultLanguage      = "zh"
)

// Envelope 是 AIG 所有 API 的统一外层响应结构。
//
//	{
//	  "status": 0,             // 0=success, 1=fail
//	  "message": "操作成功",
//	  "data": { ... }          // 根据具体接口而不同
//	}
type Envelope struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// UploadData 文件上传接口（POST /api/v1/app/taskapi/upload）的 data 字段。
type UploadData struct {
	FileURL  string `json:"fileUrl"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

// TaskCreateData 任务创建接口（POST /api/v1/app/taskapi/tasks）的 data 字段。
type TaskCreateData struct {
	SessionID string `json:"session_id"`
}

// StatusData 任务状态查询接口（GET /api/v1/app/taskapi/status/{id}）的 data 字段。
type StatusData struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	Title     string `json:"title,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	Log       string `json:"log,omitempty"`
}

// ResultData 是 /api/v1/app/taskapi/result/{id} 接口 Envelope.data 的真实结构。
//
// 经过线上抓包确认，AIG 直接把 resultUpdate 事件透传给调用方，因此 data
// 本身就是事件包装层，真正的扫描结果在 Result 字段里。
type ResultData struct {
	ID        string     `json:"id,omitempty"`
	Type      string     `json:"type,omitempty"`
	Timestamp int64      `json:"timestamp,omitempty"`
	Result    ScanResult `json:"result"`
}

// ScanResult 是 MCP scan 任务的真实结果体（AIG resultUpdate 事件中 result 字段）。
type ScanResult struct {
	// StartTime / EndTime 是带亚秒精度的 Unix 时间戳，AIG 用 float 表示，
	// 这里用 float64 保留精度。
	StartTime float64 `json:"start_time,omitempty"`
	EndTime   float64 `json:"end_time,omitempty"`

	// Language / LLM 是任务运行时的元信息，仅用于日志/审计。
	Language string `json:"language,omitempty"`
	LLM      string `json:"llm,omitempty"`

	// Readme 是任务输出的 markdown 总览（信息收集 + 关键发现），可能很长。
	Readme string `json:"readme,omitempty"`

	// Score 是 AIG 自带的安全评分（0–100），AIG 用整数返回。
	Score int `json:"score,omitempty"`

	// Results 是真正的安全问题列表。
	Results []Issue `json:"results,omitempty"`
}

// Issue 是单条安全发现，字段以线上抓包为准。
//
// 当前 mcp_scan 插件只输出以下五个字段；曾经为兼容假想中的"老版本/其它插件"
// 保留过 path 字段，但实测线上响应里从来没有出现，已删除以避免误导维护者。
type Issue struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Level       string `json:"level,omitempty"`
	RiskType    string `json:"risk_type,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ModelConfig 表示 AIG 任务请求中的 LLM 模型配置。
//
// AIG 的 mcp_scan 任务在 server 端需要 Model / Token / BaseURL **三者全部**
// 非空才能成功调用 LLM：
//   - Model：模型名（gpt-4 / deepseek-chat / kimi-k2.5 等）
//   - Token：LLM API 密钥
//   - BaseURL：LLM API endpoint，没有"合理默认值"——不同部署方使用的 LLM
//     endpoint 完全不同（自家网关 / 第三方代理 / OpenAI / DeepSeek / Kimi …），
//     必须由调用方明确指定
//
// BaseURL 的 JSON tag 故意不带 omitempty：即使为空也会被序列化发给 server，
// 让 server 端给出明确的拒绝信息，而不是被 Go 这边静默吞掉。
type ModelConfig struct {
	Model   string `json:"model"`
	Token   string `json:"token"`
	BaseURL string `json:"base_url"`
}

// HasCredentials 判断 ModelConfig 是否提供了最小可用的凭据。
// 三个字段（Model / Token / BaseURL）都必填，任意一个为空即视为未配置。
func (m ModelConfig) HasCredentials() bool {
	return m.Model != "" && m.Token != "" && m.BaseURL != ""
}

// Client 封装与 AIG 服务的交互。所有方法都是协程安全的（client.Client / *http.Client 本身协程安全）。
type Client struct {
	BaseURL      string
	HTTPClient   *http.Client
	PollInterval time.Duration
	PollTimeout  time.Duration
	MaxRetries   int

	// Model 是 mcp_scan 任务必须的 LLM 配置。
	Model ModelConfig

	// Prompt 是 mcp_scan 任务的扫描提示词描述（可选）。
	Prompt string

	// Language 控制 AIG 输出语言（zh/en），可选。
	Language string

	// Thread 控制 AIG 后端的并发线程数（>0 时生效）。
	Thread int
}
