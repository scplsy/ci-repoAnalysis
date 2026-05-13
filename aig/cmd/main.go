// Package main 是 bkrepo-aig 工具的入口。
//
// 该工具基于 analysis-tool-sdk-golang 接入蓝鲸制品库扫描框架，
// 调用开源 AI-Infra-Guard（https://github.com/Tencent/AI-Infra-Guard）
// 的 mcp_scan 任务对 MCP 源码包进行安全扫描，并把扫描得到的 issue 列表
// 转换为 SecurityResult 输出。
package main

import (
	"github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/framework"

	"github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg"
)

func main() {
	framework.Analyze(pkg.AigExecutor{})
}
