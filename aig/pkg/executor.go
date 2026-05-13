package pkg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sdkObject "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
	sdkUtil "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/util"

	"github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg/aig"
	localUtil "github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg/util"
)

// 工具参数 key 常量。
//
// 必填项：baseUrl + modelName + modelToken + modelBaseUrl
//   - baseUrl       AIG 接入地址（不同环境完全不同：本地 8088 / 内网 / SaaS / 网关 …）
//   - modelName     LLM 模型名
//   - modelToken    LLM API key
//   - modelBaseUrl  LLM API endpoint
//
// 四个 URL/凭据字段都不再有默认值兜底，缺一即在 Execute 入口被早期校验拦截。
// 其余参数均为可选；未配置或为零值时使用 aig 包中的默认值。
const (
	ArgKeyBaseURL              = "baseUrl"
	ArgKeyModelName            = "modelName"
	ArgKeyModelToken           = "modelToken"
	ArgKeyModelBaseURL         = "modelBaseUrl"
	ArgKeyPrompt               = "prompt"
	ArgKeyLanguage             = "language"
	ArgKeyThread               = "thread"
	ArgKeyUploadTimeoutSeconds = "uploadTimeoutSeconds"
	ArgKeyPollIntervalSeconds  = "pollIntervalSeconds"
	ArgKeyPollTimeoutSeconds   = "pollTimeoutSeconds"
	ArgKeyMaxRetries           = "maxRetries"
)

// AigExecutor 实现 framework.Executor 接口，
// 调用开源 AI-Infra-Guard 服务对 MCP 源码包进行安全扫描。
type AigExecutor struct{}

// Execute 执行扫描。
//
// 整体流程：
//  1. 从 ToolConfig.Args 中读取 LLM 配置（modelName/modelToken/modelBaseUrl）等参数；
//  2. 校验待扫描文件存在且非空；
//  3. 通过 AIG `POST /api/v1/app/taskapi/upload` 上传文件，获得 fileUrl；
//  4. 通过 AIG `POST /api/v1/app/taskapi/tasks` 创建 mcp_scan 任务，获得 session_id；
//  5. 周期轮询 `GET /api/v1/app/taskapi/status/{id}`；
//  6. 任务完成后调 `GET /api/v1/app/taskapi/result/{id}` 拉取结果；
//  7. 把每条 Issue 转换为 SecurityResult 输出。
func (e AigExecutor) Execute(
	ctx context.Context,
	config *sdkObject.ToolConfig,
	file *os.File,
) (*sdkObject.ToolOutput, error) {
	// 1. 读取必填项
	modelName := config.GetStringArg(ArgKeyModelName)
	modelToken := config.GetStringArg(ArgKeyModelToken)
	modelBaseURL := config.GetStringArg(ArgKeyModelBaseURL)
	aigBaseURL := config.GetStringArg(ArgKeyBaseURL)
	if modelName == "" {
		return nil, fmt.Errorf("missing required tool argument %q", ArgKeyModelName)
	}
	if modelToken == "" {
		return nil, fmt.Errorf("missing required tool argument %q", ArgKeyModelToken)
	}
	if modelBaseURL == "" {
		return nil, fmt.Errorf("missing required tool argument %q", ArgKeyModelBaseURL)
	}
	if aigBaseURL == "" {
		return nil, fmt.Errorf("missing required tool argument %q", ArgKeyBaseURL)
	}
	sdkUtil.Info("aig mcp scan started, model=%s, token=%s, modelBaseUrl=%s, aigBaseUrl=%s",
		modelName, localUtil.MaskSecret(modelToken), modelBaseURL, aigBaseURL)

	// 2. 校验文件
	if file == nil {
		return nil, errors.New("input file is nil")
	}
	filePath := file.Name()
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input file failed: %w", err)
	}
	if stat.Size() == 0 {
		return nil, fmt.Errorf("input file is empty: %s", filePath)
	}
	fileName := filepath.Base(filePath)
	sdkUtil.Info("input file resolved: name=%s, size=%d", fileName, stat.Size())

	// 3. 构造 client
	opts := buildClientOptions(config)
	client := aig.NewClientWithOptions(opts)
	sdkUtil.Info("aig client config: baseURL=%s, uploadTimeout=%s, pollInterval=%s, pollTimeout=%s, maxRetries=%d, thread=%d, language=%s",
		client.BaseURL, client.HTTPClient.Timeout, client.PollInterval, client.PollTimeout,
		client.MaxRetries, client.Thread, client.Language)

	// 4. 上传文件
	sdkUtil.Info("uploading file to AIG: %s%s", client.BaseURL, "/api/v1/app/taskapi/upload")
	uploadResp, err := client.UploadFile(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("upload file to AIG failed: %w", err)
	}
	sdkUtil.Info("upload success, fileUrl=%s, size=%d", uploadResp.FileURL, uploadResp.Size)

	// 5. 创建 mcp_scan 任务
	taskResp, err := client.CreateMcpScanTask(ctx, uploadResp.FileURL)
	if err != nil {
		return nil, fmt.Errorf("create mcp_scan task failed: %w", err)
	}
	sessionID := taskResp.SessionID
	sdkUtil.Info("mcp_scan task created, sessionId=%s", sessionID)

	// 6. 轮询并拉取结果
	resultResp, err := client.WaitForResult(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	scan := resultResp.Result
	sdkUtil.Info("aig mcp scan finished, sessionId=%s, issues=%d, score=%d, llm=%s, language=%s, duration=%.2fs",
		sessionID, len(scan.Results), scan.Score, scan.LLM, scan.Language, scan.EndTime-scan.StartTime)

	// 7. 转换为 SecurityResult
	securityResults := BuildSecurityResults(sessionID, scan, fileName)
	sdkUtil.Info("generated %d security result(s)", len(securityResults))

	return sdkObject.NewOutput(
		sdkObject.StatusSuccess,
		&sdkObject.Result{SecurityResults: securityResults},
		nil,
	), nil
}

// buildClientOptions 从 ToolConfig 中读取可选参数，转换为 aig.ClientOptions。
//
// 参数读取表：
//   - baseUrl              (STRING, 必填)：AIG 接入地址（无默认值，必须明确指定）
//   - modelName            (STRING, 必填)：LLM 模型名称
//   - modelToken           (STRING, 必填)：LLM API 密钥
//   - modelBaseUrl         (STRING, 必填)：LLM API base URL（无默认值，必须明确指定）
//   - prompt               (STRING)：附加扫描提示词
//   - language             (STRING)：输出语言（zh/en）
//   - thread               (NUMBER)：AIG 后端并发线程数
//   - uploadTimeoutSeconds (NUMBER)：上传请求超时，单位秒
//   - pollIntervalSeconds  (NUMBER)：轮询间隔，单位秒
//   - pollTimeoutSeconds   (NUMBER)：轮询总超时，单位秒
//   - maxRetries           (NUMBER)：查询错误重试次数
//
// 任何 NUMBER 参数解析失败或为非正数都会保留 ClientOptions 中的零值，
// 由 aig.NewClientWithOptions 负责回退到默认值。
func buildClientOptions(config *sdkObject.ToolConfig) aig.ClientOptions {
	opts := aig.ClientOptions{
		BaseURL:  config.GetStringArg(ArgKeyBaseURL),
		Prompt:   config.GetStringArg(ArgKeyPrompt),
		Language: config.GetStringArg(ArgKeyLanguage),
		Model: aig.ModelConfig{
			Model:   config.GetStringArg(ArgKeyModelName),
			Token:   config.GetStringArg(ArgKeyModelToken),
			BaseURL: config.GetStringArg(ArgKeyModelBaseURL),
		},
	}
	if v, err := config.GetIntArg(ArgKeyThread); err == nil && v > 0 {
		opts.Thread = int(v)
	}
	if v, err := config.GetIntArg(ArgKeyUploadTimeoutSeconds); err == nil && v > 0 {
		opts.UploadTimeout = time.Duration(v) * time.Second
	}
	if v, err := config.GetIntArg(ArgKeyPollIntervalSeconds); err == nil && v > 0 {
		opts.PollInterval = time.Duration(v) * time.Second
	}
	if v, err := config.GetIntArg(ArgKeyPollTimeoutSeconds); err == nil && v > 0 {
		opts.PollTimeout = time.Duration(v) * time.Second
	}
	if v, err := config.GetIntArg(ArgKeyMaxRetries); err == nil && v > 0 {
		opts.MaxRetries = int(v)
	}
	return opts
}
