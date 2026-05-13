// Package pkg 实现 analysis-tool-sdk-golang 中定义的 Executor 接口，
// 把 AIG（AI-Infra-Guard）的 mcp_scan 能力包装为蓝鲸制品库扫描工具。
package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	sdkObject "github.com/TencentBlueKing/ci-repoAnalysis/analysis-tool-sdk-golang/object"

	"github.com/TencentBlueKing/ci-repoAnalysis/aig/pkg/aig"
)

// SDK 中 SecurityResult.Severity 的取值范围（小写）。
//
// 参考 ci-repoAnalysis/docs/development.md 的 result.securityResults 字段说明。
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
)

// 默认漏洞名：当 AIG 未返回 title / risk_type 时使用。
const defaultVulName = "AIG_MCP_RISK"

// 默认描述：当 AIG description / suggestion 都缺失时占位。
const defaultDescription = "AIG mcp scan reported a risk without further description"

// vulIDPrefix 是所有本扫描器产出的 VulId 的统一前缀。
//
// 用途：在制品库漏洞表里能一眼区分 AIG mcp_scan 与其它扫描器（trivy /
// bandit / ...）的产物；如果未来需要做来源筛选 / 批量清理，按前缀过滤即可。
// 改动该值会让历史 VulId 全部失效，请谨慎。
const vulIDPrefix = "aig-"

// vulIDHashLen 是 VulId 截取的 sha256 hex 长度（64bit，足以避免实际碰撞）。
const vulIDHashLen = 16

// AIG description / suggestion 解析相关正则。
//
//   - filePathLineRe 匹配形如 `  **文件位置**: /path/to/file` 的单行，
//     容忍前导空格、中英文冒号。
//   - aigTmpPrefixRe 用于剥离 AIG 服务端的容器内临时目录前缀，
//     形如 `/app/agent-scan/uploads/tmp-<id>/`。
//   - sectionHeaderRe 用于定位 description 中的三级标题（### XXX）。
//   - solutionHeaderRe 用于剥离 suggestion 开头的 `## 修复建议` 二级标题行（含
//     可能的尾随换行），让 Solution 字段直接以正文起头。
var (
	filePathLineRe   = regexp.MustCompile(`(?m)^\s*\*\*文件位置\*\*\s*[:：]\s*(\S+)\s*$`)
	aigTmpPrefixRe   = regexp.MustCompile(`^/app/agent-scan/uploads/tmp-[^/]+/`)
	sectionHeaderRe  = regexp.MustCompile(`(?m)^[ \t]*###[ \t]+(.+?)[ \t]*$`)
	solutionHeaderRe = regexp.MustCompile(`\A[ \t]*##[ \t]+修复建议[ \t]*(?:\r?\n|\z)`)
)

// wantedSections 是 description 中需要保留进入 Des 字段的章节白名单。
//
// AIG mcp_scan 当前会在 description 里输出「漏洞详情/技术分析/攻击路径/影响评估」
// 等多个 ### 子段，前端只关心后三段，前缀的「漏洞详情」中已包含的文件位置
// 等元信息会在 Path / VulName 等专用字段中体现，无需重复展示。
var wantedSections = map[string]struct{}{
	"技术分析": {},
	"攻击路径": {},
	"影响评估": {},
}

// BuildSecurityResults 把 AIG mcp_scan 返回的 ScanResult 转换为 SDK 标准的 SecurityResult 列表。
//
// 入参形态选择：直接接收 aig.ScanResult（即 ResultData.Result），让函数定位
// 在「把一次扫描的结果体翻译成 SDK 输出」这一概念上；任务级元信息
// （Score/Readme/StartTime 等）属于任务整体而非单条漏洞，由调用方负责打日志。
//
// 转换规则：
//  1. scan.Results 为空 → 返回空切片（即扫描没有发现风险，零结果）。
//  2. 每条 issue 输出一条 SecurityResult：
//     - VulId    = 由 sessionID + riskType + title + level 派生的稳定 ID
//     （详见 buildVulID 注释），所有 VulId 都以 "aig-" 前缀开头
//     - VulName  = issue.Title；缺省时 fallback 到 risk_type / 默认值
//     - Des      = 从 description 中提取的「技术分析/攻击路径/影响评估」三段；
//     若都解析不到则回退到原始 description；description/suggestion 全空时占位
//     - Solution = issue.Suggestion 原样输出（空字符串则保持空）
//     - Path     = description 中 **文件位置** 字段去掉 AIG 临时目录前缀后的相对路径；
//     description 中无该字段时回退到 fileName
//     - PkgName  = fileName（始终是上传的压缩包名）
//     - Severity 映射：见 severityFromLevel
func BuildSecurityResults(sessionID string, scan aig.ScanResult, fileName string) []sdkObject.SecurityResult {
	if len(scan.Results) == 0 {
		return []sdkObject.SecurityResult{}
	}
	results := make([]sdkObject.SecurityResult, 0, len(scan.Results))
	for _, issue := range scan.Results {
		results = append(results, buildOneSecurityResult(sessionID, issue, fileName))
	}
	return results
}

func buildOneSecurityResult(sessionID string, issue aig.Issue, fileName string) sdkObject.SecurityResult {
	return sdkObject.SecurityResult{
		VulId:   buildVulID(sessionID, issue),
		VulName: chooseVulName(issue),
		Path:    choosePath(issue, fileName),
		PkgName: fileName,
		// 显式初始化为空切片，避免 encoding/json 把 nil slice 序列化为 null。
		// SDK 中 PkgVersions/References 没有 omitempty，服务端期望得到 [] 而非 null。
		PkgVersions: []string{},
		References:  []string{},
		Des:         buildDescription(issue),
		Solution:    buildSolution(issue),
		Severity:    severityFromLevel(issue.Level),
	}
}

// buildVulID 生成漏洞库主键 VulId。
//
// 设计目标：
//   - 稳定：同一 sessionID + 同一 issue 关键字段 → 相同 VulId，扫描器版本升级不应影响
//   - 可区分：不同 sessionID / 不同 title / 不同 risk_type / 不同 level → 不同 VulId
//   - 不依赖可变字段：description / suggestion 是自然语言，会随插件迭代变化，
//     **不**纳入 VulId 派生源
//   - 统一前缀：所有 VulId 都以 vulIDPrefix（"aig-"）开头，便于按来源筛选
//
// 派生公式：
//
//	VulId = "aig-" + sha256(sessionID|riskType|title|level)[:16]
//
// 当所有派生字段均为空时，仍能产生稳定（虽然全冲突）的 VulId。
func buildVulID(sessionID string, issue aig.Issue) string {
	parts := []string{
		strings.TrimSpace(sessionID),
		strings.TrimSpace(issue.RiskType),
		strings.TrimSpace(issue.Title),
		strings.ToLower(strings.TrimSpace(issue.Level)),
	}
	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	return vulIDPrefix + hex.EncodeToString(sum[:])[:vulIDHashLen]
}

// chooseVulName 选择 SecurityResult 的 VulName：
//
// 优先级：title > risk_type > defaultVulName。
func chooseVulName(issue aig.Issue) string {
	if t := strings.TrimSpace(issue.Title); t != "" {
		return t
	}
	if rt := strings.TrimSpace(issue.RiskType); rt != "" {
		return rt
	}
	return defaultVulName
}

// choosePath 从 issue.Description 中解析 `**文件位置**: <path>` 行，
// 剥离 AIG 服务端的容器内临时目录前缀（/app/agent-scan/uploads/tmp-<id>/），
// 把得到的相对路径（如 `skill-vul-test/SKILL.md`）作为 SecurityResult.Path。
//
// 当 description 中找不到该行时，回退到 fileName，保持与历史行为一致。
func choosePath(issue aig.Issue, fileName string) string {
	m := filePathLineRe.FindStringSubmatch(issue.Description)
	if len(m) < 2 {
		return fileName
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" {
		return fileName
	}
	return aigTmpPrefixRe.ReplaceAllString(raw, "")
}

// buildDescription 从 issue.Description 中按章节提取并拼接成新的 Des。
//
// 规则：
//   - 只保留三段：`### 技术分析` / `### 攻击路径` / `### 影响评估`（顺序按文档原序）。
//   - 保留 `###` 标题本身，章节之间用一个空行分隔。
//   - 任意目标章节都解析不到时，回退到原始 description（避免在文档格式变更后丢信息）。
//   - description 为空 → defaultDescription 占位（与 suggestion 是否为空无关，
//     suggestion 现在独立落到 Solution 字段）。
func buildDescription(issue aig.Issue) string {
	desc := strings.TrimSpace(issue.Description)
	if desc == "" {
		return defaultDescription
	}
	sections := extractWantedSections(issue.Description)
	if len(sections) == 0 {
		return desc
	}
	return strings.Join(sections, "\n\n")
}

// extractWantedSections 扫描 description 中所有 `###` 标题，
// 把命中 wantedSections 白名单的章节（含标题）按出现顺序拼成 markdown 片段返回。
//
// 每段输出格式：`### <title>\n<body>`，body 已做 trim 与统一前导空格清理。
// 未命中任何白名单时返回 nil，由调用方决定 fallback 策略。
func extractWantedSections(description string) []string {
	matches := sectionHeaderRe.FindAllStringSubmatchIndex(description, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for i, m := range matches {
		// m = [matchStart, matchEnd, group1Start, group1End]
		headerEnd := m[1]
		titleStart, titleEnd := m[2], m[3]
		title := strings.TrimSpace(description[titleStart:titleEnd])
		if _, ok := wantedSections[title]; !ok {
			continue
		}
		bodyEnd := len(description)
		if i+1 < len(matches) {
			bodyEnd = matches[i+1][0]
		}
		body := description[headerEnd:bodyEnd]
		body = dedentBlock(body)
		body = strings.Trim(body, "\n")
		section := "### " + title
		if body != "" {
			section = section + "\n" + body
		}
		out = append(out, section)
	}
	return out
}

// dedentBlock 去掉一个文本块每行公共的前导空白（最少缩进的那一行决定缩进基线），
// 解决 AIG description 中每段正文都带 2 空格缩进、直接拼到 Des 后渲染走样的问题。
//
// 仅按空格/Tab 字符判定，纯空行不参与缩进基线计算。
func dedentBlock(s string) string {
	lines := strings.Split(s, "\n")
	minIndent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && (line[indent] == ' ' || line[indent] == '\t') {
			indent++
		}
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}
	if minIndent <= 0 {
		return s
	}
	for i, line := range lines {
		if len(line) >= minIndent {
			lines[i] = line[minIndent:]
		}
	}
	return strings.Join(lines, "\n")
}

// buildSolution 把 issue.Suggestion 转换为 SecurityResult.Solution。
//
// 规则：
//   - 剥离开头的 `## 修复建议` 二级标题行（AIG 模板里固定带的前缀，对消费端无价值）。
//   - 剥离剩余正文每行公共的前导缩进（AIG 模板每行带 2 空格缩进，避免 markdown 被解析为代码块）。
//   - trim 首尾空白。
//   - 空字符串保持空，不强制占位（由消费端决定要不要展示空 Solution）。
func buildSolution(issue aig.Issue) string {
	if strings.TrimSpace(issue.Suggestion) == "" {
		return ""
	}
	// 注意：先 ReplaceAll 再 dedent，最后 TrimSpace。
	// 不要在最前面 TrimSpace —— 那会吃掉第一行的公共前导缩进，
	// 让 dedentBlock 误以为 minIndent=0 而漏剥后续行的缩进。
	s := solutionHeaderRe.ReplaceAllString(issue.Suggestion, "")
	s = dedentBlock(s)
	return strings.TrimSpace(s)
}

// severityFromLevel 把 AIG 的 level 映射到 SDK 的 severity 取值。
//
// 大小写不敏感，未识别的取值统一回退到 low。
// 同时兼容内部 AIG 使用的 malicious / suspicious 命名。
func severityFromLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "malicious":
		return severityCritical
	case "high":
		return severityHigh
	case "medium", "suspicious", "warning":
		return severityMedium
	default:
		return severityLow
	}
}
