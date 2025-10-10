package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/util"
)

const PackageTypeNpm = "NPM"

// DependencyCheckExecutor DependencyCheck分析器
type DependencyCheckExecutor struct{}

// Execute 执行分析
func (e DependencyCheckExecutor) Execute(
	ctx context.Context,
	config *object.ToolConfig,
	file *os.File,
) (*object.ToolOutput, error) {
	offline, err := config.GetBoolArg(ConfigOffline)
	if err != nil {
		return nil, err
	}

	inputFile := file.Name()
	if config.GetStringArg(util.ArgKeyPkgType) == PackageTypeNpm {
		if err := npmPrepare(ctx, file); err != nil {
			return nil, err
		}
		inputFile = filepath.Join(filepath.Dir(inputFile), "package-lock.json")
	}

	// 下载漏洞库
	stop := util.StartTimer(ctx, "downloadDBTime")
	downloader := &util.DefaultDownloader{}
	dbUrl := config.GetStringArg(ConfigDbUrl)
	if len(dbUrl) > 0 {
		if err := util.ExtractTarUrl(dbUrl, DirDependencyCheckData, 0770, downloader); err != nil {
			return nil, err
		}
	}
	stop()

	// 执行扫描
	reportFile, err := doExecute(ctx, inputFile, offline)
	if err != nil {
		return nil, err
	}
	return transform(reportFile, util.Metrics(ctx))
}

func npmPrepare(ctx context.Context, file *os.File) error {
	stop := util.StartTimer(ctx, "npmPrepareTime")
	defer stop()
	fileAbsPath := file.Name()
	fileBaseName := filepath.Base(fileAbsPath)
	workDir := filepath.Dir(fileAbsPath)

	// npm install
	if err := util.ExecAndLog(ctx, "npm", []string{"install", file.Name()}, workDir); err != nil {
		return err
	}

	// 获取 pkgName 和 pkgVersion
	pkgName, pkgVersion, err := ExtractPackageNameAndVersion(fileAbsPath)
	if err != nil {
		return err
	}
	if len(pkgName) == 0 || len(pkgVersion) == 0 {
		pkgName, pkgVersion = ParsePackageNameAndVersion(fileBaseName)
	}
	if len(pkgName) == 0 || len(pkgVersion) == 0 {
		return errors.New("failed to parse npm pkgName and pkgVersion")
	}
	util.Info("npm package %s, version %s", pkgName, pkgVersion)

	// 替换 package-lock.json中的file:xxx 为实际版本号
	sedExp := fmt.Sprintf(
		"s|\\\"%s\\\": \\\"file:%s\\\"|\\\"%s\\\": \\\"%s\\\"|",
		pkgName, fileBaseName, pkgName, pkgVersion,
	)
	if err := sed(ctx, sedExp, filepath.Join(workDir, "package-lock.json")); err != nil {
		return err
	}
	if err := sed(ctx, sedExp, filepath.Join(workDir, "package.json")); err != nil {
		return err
	}

	sedExp = fmt.Sprintf(
		"s|\\\"version\\\": \\\"file:%s\\\"|\\\"version\\\": \\\"%s\\\"|",
		fileBaseName, pkgVersion,
	)
	if err := sed(ctx, sedExp, filepath.Join(workDir, "package-lock.json")); err != nil {
		return err
	}
	return nil
}

func sed(ctx context.Context, exp string, fileAbsPath string) error {
	args := []string{"-i", exp, fileAbsPath}
	if err := util.ExecAndLog(ctx, "sed", args, ""); err != nil {
		return err
	}
	return nil
}

// doExecute 执行扫描，扫描成功后返回报告路径
func doExecute(ctx context.Context, inputFile string, offline bool) (string, error) {
	// dependency-check.sh --scan /src --format JSON --out /report

	const reportFile = "/report"
	args := []string{
		"--scan", inputFile,
		"--format", "JSON",
		"--out", reportFile,
	}

	if offline {
		args = append(
			args, "--noupdate",
			"--disableYarnAudit", "--disablePnpmAudit", "--disableNodeAudit", "--disableOssIndex", "--disableCentral")
	}

	if err := util.ExecAndLog(ctx, CMDDependencyCheck, args, ""); err != nil {
		return "", err
	}

	return reportFile + "/dependency-check-report.json", nil
}

// transform 转换DependencyCheck输出的报告为制品库扫描结果格式
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
