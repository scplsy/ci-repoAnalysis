package pkg

import (
	"context"
	"encoding/json"
	"os"

	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/util"
)

// Scancode 扫描器
type Scancode struct{}

// Execute 执行扫描
func (e Scancode) Execute(ctx context.Context, config *object.ToolConfig, file *os.File) (*object.ToolOutput, error) {
	//extractcode /path/to/inputFile
	if err := util.ExecAndLog(ctx, "extractcode", []string{file.Name()}, ""); err != nil {
		return nil, err
	}
	util.Info("success extract file %s", file.Name())

	//scancode --license-score 100 --license --max-depth 4 -n 4 --only-findings --json resultFile inputFile-extract
	resultFile := "/bkrepo/workspace/result.json"
	args := []string{
		"--license-score", "100",
		"--license",
		"--max-depth", "4",
		"-n", "4",
		"--only-findings",
		"--json", resultFile,
		file.Name() + "-extract",
	}

	if err := util.ExecAndLog(ctx, "scancode", args, ""); err != nil {
		return nil, err
	}

	return transform(resultFile, util.Metrics(ctx))
}

// transform 转换输出报告为标准格式
func transform(reportFile string, metrics map[string]any) (*object.ToolOutput, error) {
	reportContent, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, err
	}

	report := new(Report)
	if err := json.Unmarshal(reportContent, report); err != nil {
		return nil, err
	}

	return object.NewOutput(object.StatusSuccess, Convert(report), metrics), nil
}
