package framework

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/api"
	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"
	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/util"
)

// Executor 分析执行器
type Executor interface {
	// Execute 框架会调用该函数执行扫描，传入的参数config为工具相关配置，file为待分析的制品
	// 扫描成功时返回toolOutput，出错时返回error，工具框架会自动上报或输出结果给制品分析服务
	Execute(ctx context.Context, config *object.ToolConfig, file *os.File) (*object.ToolOutput, error)
}

// Analyze 执行分析
func Analyze(executor Executor) {
	args := object.GetArgs()
	for {
		util.Info("start analyze")
		doAnalyze(executor, args)
		util.Info("keep running %t", args.ShouldKeepRunning())
		if args.ShouldKeepRunning() {
			if err := util.CleanWorkDir(); err != nil {
				panic("clean work dir failed: " + err.Error())
			}
			util.Info("clean workdir success")
		} else {
			util.Info("analyze finished")
			break
		}
	}
}

func doAnalyze(executor Executor, arguments *object.Arguments) {
	ctx, cancel := util.NewRootContext()
	defer cancel()

	client := api.GetClient(arguments)
	input, err := client.Start(ctx, cancel)
	if err != nil {
		panic("Start analyze failed: " + err.Error())
	}
	if input == nil || input.TaskId == "" {
		util.Info("no subtask found, exit")
		return
	}
	stop := util.StartTimer(ctx, "generateInputFileTime")
	file, err := client.GenerateInputFile()
	if err != nil {
		client.Failed(util.Metrics(ctx), cancel, errors.New("Generate input file failed: "+err.Error()))
		return
	}
	// 返回的file为nil时表示文件被忽略，直接返回
	if file == nil {
		util.Info("Unsupported filename: %s", input.FileUrls[0].Name)
		client.Finish(cancel, object.NewOutput(object.StatusSuccess, new(object.Result), util.Metrics(ctx)))
		return
	}
	stop()
	defer file.Close()
	util.Info("generate input file success")
	execCtx, execCancel := util.NewTimeoutContext(ctx, client.ToolInput.MaxTime())
	defer execCancel()
	stop = util.StartTimer(ctx, "executeTime")
	output, err := executor.Execute(execCtx, &input.ToolConfig, file)
	stop()
	if err != nil {
		errMsg := "Execute analysis failed: " + err.Error()
		if ctx.Err() != nil {
			errMsg = fmt.Sprintf("%s, ctx err[%s]", errMsg, ctx.Err().Error())
		}
		client.Failed(util.Metrics(ctx), cancel, errors.New(errMsg))
	} else {
		output.Metrics = util.Metrics(ctx)
		client.Finish(cancel, output)
	}
}
