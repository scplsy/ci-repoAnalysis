package aig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// CreateMcpScanTask 创建 mcp_scan 类型的扫描任务，并返回 session_id。
//
// 接口路径：POST {BaseURL}/api/v1/app/taskapi/tasks
// 请求体：
//
//	{
//	  "type": "mcp_scan",
//	  "content": {
//	    "model": {"model": "...", "token": "...", "base_url": "..."},
//	    "thread": 4,
//	    "language": "zh",
//	    "attachments": "<file_url>",
//	    "prompt": "..."           // 可选
//	  }
//	}
//
// 调用前必须保证 c.Model.HasCredentials()==true，否则返回 ErrMissingModelCredentials。
func (c *Client) CreateMcpScanTask(ctx context.Context, fileURL string) (*TaskCreateData, error) {
	if !c.Model.HasCredentials() {
		return nil, ErrMissingModelCredentials
	}
	if fileURL == "" {
		return nil, errors.New("create mcp_scan task failed: empty fileUrl")
	}

	content := map[string]any{
		"model":       c.Model,
		"thread":      c.Thread,
		"language":    c.Language,
		"attachments": fileURL,
	}
	if c.Prompt != "" {
		content["prompt"] = c.Prompt
	}

	payload := map[string]any{
		"type":    TaskTypeMcpScan,
		"content": content,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal task body failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+taskPath, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build task request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send task request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read task response failed: %w", err)
	}

	var data TaskCreateData
	if err := decodeEnvelope(resp.StatusCode, respBytes, "create mcp_scan task", &data); err != nil {
		return nil, err
	}
	if data.SessionID == "" {
		return nil, fmt.Errorf("create mcp_scan task failed: missing session_id, raw=%s", string(respBytes))
	}
	return &data, nil
}

// ErrMissingModelCredentials 表示 ModelConfig 中三个必填字段
// （model / token / base_url）至少有一个为空。
var ErrMissingModelCredentials = errors.New("missing required model fields: model/token/base_url must all be non-empty")
