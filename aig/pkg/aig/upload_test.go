package aig

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClient 把 Client 指向 httptest.Server 并把超时缩短，便于快速失败。
func newTestClient(server *httptest.Server) *Client {
	c := NewClient()
	c.BaseURL = strings.TrimRight(server.URL, "/")
	c.HTTPClient = server.Client()
	c.HTTPClient.Timeout = 5 * time.Second
	c.PollInterval = 10 * time.Millisecond
	c.PollTimeout = 2 * time.Second
	c.MaxRetries = 2
	c.Model = ModelConfig{Model: "gpt-4", Token: "sk-test", BaseURL: "https://api.openai.com/v1"}
	return c
}

func writeTempFile(t *testing.T, name, data string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}
	return p
}

func TestUploadFile_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/app/taskapi/upload" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("unexpected content-type: %s", ct)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("parse multipart failed: %v", err)
		}
		if _, ok := r.MultipartForm.File[MultipartFieldFile]; !ok {
			t.Errorf("expected multipart field %s missing", MultipartFieldFile)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w,
			`{"status":0,"message":"ok","data":{"fileUrl":"http://localhost:8088/uploads/x.zip","filename":"x.zip","size":42}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	filePath := writeTempFile(t, "x.zip", "fake content")
	resp, err := c.UploadFile(context.Background(), filePath)
	if err != nil {
		t.Fatalf("UploadFile returned error: %v", err)
	}
	if resp.FileURL != "http://localhost:8088/uploads/x.zip" {
		t.Errorf("FileURL = %q", resp.FileURL)
	}
	if resp.Size != 42 {
		t.Errorf("Size = %d", resp.Size)
	}
}

func TestUploadFile_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":1,"message":"file required","data":null}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.UploadFile(context.Background(), writeTempFile(t, "x.zip", "data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "file required") {
		t.Errorf("expected message in error, got: %v", err)
	}
}

func TestUploadFile_MissingFileURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":0,"message":"ok","data":{"filename":"x.zip"}}`)
	}))
	defer server.Close()

	c := newTestClient(server)
	_, err := c.UploadFile(context.Background(), writeTempFile(t, "x.zip", "data"))
	if err == nil {
		t.Fatal("expected error for missing fileUrl")
	}
}

func TestUploadFile_MissingFile(t *testing.T) {
	c := newTestClient(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	_, err := c.UploadFile(context.Background(), "/no/such/file.zip")
	if err == nil {
		t.Fatal("expected error opening file")
	}
}
