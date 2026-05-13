package aig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/util"
)

// QueryStatus 调用 GET /api/v1/app/taskapi/status/{id} 查询单次任务状态。
func (c *Client) QueryStatus(ctx context.Context, sessionID string) (*StatusData, error) {
	url := c.BaseURL + fmt.Sprintf(statusPathFmt, sessionID)
	respBytes, status, err := c.doGET(ctx, url)
	if err != nil {
		return nil, err
	}

	var data StatusData
	if err := decodeEnvelope(status, respBytes, "query task status", &data); err != nil {
		return nil, err
	}
	if data.Status == "" {
		return nil, fmt.Errorf("query task status failed: missing status field, raw=%s", string(respBytes))
	}
	return &data, nil
}

// QueryResult 调用 GET /api/v1/app/taskapi/result/{id} 拉取扫描结果。
func (c *Client) QueryResult(ctx context.Context, sessionID string) (*ResultData, error) {
	url := c.BaseURL + fmt.Sprintf(resultPathFmt, sessionID)
	respBytes, status, err := c.doGET(ctx, url)
	if err != nil {
		return nil, err
	}

	var data ResultData
	if err := decodeEnvelope(status, respBytes, "query task result", &data); err != nil {
		return nil, err
	}
	if len(data.Result.Results) == 0 {
		util.Warn("aig task[%s] result has no issues, score=%d, raw=%s",
			sessionID, data.Result.Score, string(respBytes))
	} else {
		util.Info("aig task[%s] result fetched: issues=%d, score=%d, llm=%s, language=%s",
			sessionID, len(data.Result.Results), data.Result.Score, data.Result.LLM, data.Result.Language)
	}
	return &data, nil
}

// WaitForResult 周期性轮询 AIG 任务状态直到进入终态，并在完成时拉取扫描结果。
//
// 轮询行为：
//   - 间隔为 c.PollInterval（默认 5s）
//   - 总等待时间不超过 c.PollTimeout（默认 30 分钟）
//   - 单次状态查询出现网络错误时进行最多 c.MaxRetries（默认 3）次重试，
//     连续失败超过阈值时返回错误
//   - 当 status==failed 时，返回错误并把任务日志附加到错误信息中
func (c *Client) WaitForResult(ctx context.Context, sessionID string) (*ResultData, error) {
	deadline := time.Now().Add(c.PollTimeout)
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	failures := 0
	attempt := 0
	for {
		attempt++
		stat, err := c.QueryStatus(pollCtx, sessionID)
		if err != nil {
			if pollCtx.Err() != nil {
				return nil, fmt.Errorf("poll task status timeout after %s: %w", c.PollTimeout, err)
			}
			failures++
			util.Warn("query task[%s] status failed (attempt=%d, failures=%d/%d): %s",
				sessionID, attempt, failures, c.MaxRetries, err.Error())
			if failures > c.MaxRetries {
				return nil, fmt.Errorf("query task status failed after %d retries: %w", c.MaxRetries, err)
			}
			if waitErr := sleepCtx(pollCtx, c.PollInterval); waitErr != nil {
				return nil, fmt.Errorf("poll task canceled: %w", waitErr)
			}
			continue
		}
		failures = 0

		switch stat.Status {
		case TaskStatusCompleted:
			util.Info("task[%s] completed, fetching result", sessionID)
			return c.QueryResult(pollCtx, sessionID)
		case TaskStatusFailed, TaskStatusTerminated:
			logSnippet := truncateLog(stat.Log, 1024)
			if logSnippet == "" {
				logSnippet = "no log provided"
			}
			return nil, fmt.Errorf("aig task[%s] failed: %s", sessionID, logSnippet)
		default:
			util.Info("task[%s] in progress, status=%s, will retry in %s",
				sessionID, stat.Status, c.PollInterval)
		}

		if waitErr := sleepCtx(pollCtx, c.PollInterval); waitErr != nil {
			if errors.Is(waitErr, context.DeadlineExceeded) {
				return nil, fmt.Errorf("poll task timeout after %s", c.PollTimeout)
			}
			return nil, fmt.Errorf("poll task canceled: %w", waitErr)
		}
	}
}

// doGET 发送 GET 请求并读取 body，返回 (body, httpStatus, err)。
//
// 单次查询请求使用更短的超时（DefaultQueryTimeout），避免单次轮询长时间阻塞，
// 不复用 c.HTTPClient.Timeout（后者是为大文件上传保留的较长超时）。
func (c *Client) doGET(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build GET request failed: %w", err)
	}

	httpClient := &http.Client{Timeout: DefaultQueryTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("send GET request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read GET response failed: %w", err)
	}
	return body, resp.StatusCode, nil
}

// sleepCtx 在等待期间响应 ctx 的取消/超时。
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// truncateLog 截断过长的任务日志，避免错误信息过长。
func truncateLog(log string, max int) string {
	if max <= 0 || len(log) <= max {
		return log
	}
	return log[:max] + "...(truncated)"
}
