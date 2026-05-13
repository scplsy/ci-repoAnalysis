package aig

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
)

// 默认上传文件的 Content-Type；AIG 上传接口接受 zip/json/txt 等多种类型，
// 这里固定为 application/zip，与 mcp_scan 源码扫描场景一致。
const defaultUploadContentType = "application/zip"

// UploadFile 把待扫描的本地文件以 multipart/form-data 形式上传到 AIG，
// 接口路径为 POST {BaseURL}/api/v1/app/taskapi/upload，返回 fileUrl。
//
// 上传体采用流式管道（io.Pipe）实现，内存占用与文件大小无关。
func (c *Client) UploadFile(ctx context.Context, filePath string) (*UploadData, error) {
	body, contentType, err := buildUploadBody(filePath)
	if err != nil {
		return nil, fmt.Errorf("build multipart body failed: %w", err)
	}
	defer body.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+uploadPath, body)
	if err != nil {
		return nil, fmt.Errorf("build upload request failed: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send upload request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upload response failed: %w", err)
	}

	var data UploadData
	if err := decodeEnvelope(resp.StatusCode, respBytes, "upload file", &data); err != nil {
		return nil, err
	}
	if data.FileURL == "" {
		return nil, fmt.Errorf("upload file failed: missing fileUrl in response, raw=%s", string(respBytes))
	}
	return &data, nil
}

// buildUploadBody 以流式方式构造 multipart/form-data 请求体。
//
// 字段名为 file，filename 为文件原始名称，
// Content-Type 默认 application/zip。
//
// 实现原理：使用 io.Pipe 把 multipart 编码端与 HTTP 发送端解耦：
//   - 后台 goroutine 打开文件、写入 multipart writer，最终写入 PipeWriter；
//   - 调用方拿到 PipeReader 作为 HTTP 请求体；
//   - 整条管道仅占用一份小缓冲（io.Copy 默认 32KB），与文件大小无关，
//     避免大文件被全量读入内存导致 OOM。
//
// 错误传递：goroutine 内任何步骤出错都会通过 pw.CloseWithError 反映到读取端，
// 让 http.Client.Do 收到错误并返回。
//
// 资源释放：调用方使用完返回的 io.ReadCloser 后必须调用 Close()，
// 这会唤醒可能阻塞在 Write 的 goroutine 并触发其 defer 释放文件句柄。
func buildUploadBody(filePath string) (io.ReadCloser, string, error) {
	// 提前打开文件，便于在调用方收到「文件不存在/权限错误」时同步返回，
	// 而不是等到 HTTP 请求开始读 body 才异步暴露错误。
	f, err := os.Open(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("open upload file failed: %w", err)
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	contentType := writer.FormDataContentType()

	go func() {
		var copyErr error
		defer func() {
			// 顺序：先关 multipart writer 写入结尾 boundary，
			// 再关 pipe，最后关闭文件。
			if cerr := writer.Close(); cerr != nil && copyErr == nil {
				copyErr = cerr
			}
			_ = pw.CloseWithError(copyErr)
			_ = f.Close()
		}()

		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name=%q; filename=%q`,
				MultipartFieldFile, filepath.Base(filePath)))
		header.Set("Content-Type", defaultUploadContentType)

		part, err := writer.CreatePart(header)
		if err != nil {
			copyErr = fmt.Errorf("create multipart part failed: %w", err)
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			copyErr = fmt.Errorf("copy file to multipart failed: %w", err)
			return
		}
	}()

	return pr, contentType, nil
}
