## AIG MCP 源码扫描器

基于 [analysis-tool-sdk-golang](https://github.com/TencentBlueKing/ci-repoAnalysis/tree/master/analysis-tool-sdk-golang) 实现的蓝鲸制品库 standard 扫描器，对接 [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) `mcp_scan` 任务。

工作流程：

1. 上传待扫描的 MCP 源码 zip 包到 AIG（`POST /api/v1/app/taskapi/upload`）
2. 创建 `mcp_scan` 类型的任务（`POST /api/v1/app/taskapi/tasks`）
3. 周期轮询任务状态（`GET /api/v1/app/taskapi/status/{id}`）
4. 任务完成后拉取扫描结果（`GET /api/v1/app/taskapi/result/{id}`）
5. 把每条 issue 转换为 `SecurityResult` 输出

## 工具参数

所有参数都通过 `analysis-tool-sdk-golang` 的 `ToolConfig.Args` 传入，由代码直接读取（**不通过** `tool.json` 模板化）。

| 参数名                  | 类型    | 必填 | 默认值                  | 说明                                              |
|-------------------------|---------|------|-------------------------|---------------------------------------------------|
| `modelName`             | STRING  | 是   | -                       | LLM 模型名（如 `gpt-4`、`deepseek-chat`、`kimi-k2.5`） |
| `modelToken`            | STRING  | 是   | -                       | LLM API key                                       |
| `modelBaseUrl`          | STRING  | 是   | -                       | LLM API base URL，**无默认值，必须由调用方明确提供**（不同部署方使用的 endpoint 完全不同：自家网关 / 第三方代理 / OpenAI / DeepSeek / Kimi …） |
| `baseUrl`               | STRING  | 是   | -                       | AIG 服务接入地址，**无默认值，必须由调用方明确提供**（不同环境的 AIG 接入地址完全不同：本地 8088 / 公司内网 / SaaS / 自建网关 …） |
| `prompt`                | STRING  | 否   | -                       | 附加的扫描提示词                                  |
| `language`              | STRING  | 否   | `zh`                    | AIG 输出语言（`zh` / `en`）                       |
| `thread`                | NUMBER  | 否   | `4`                     | AIG 后端并发线程数                                |
| `uploadTimeoutSeconds`  | NUMBER  | 否   | `300`                   | 单次上传请求超时（秒）                            |
| `pollIntervalSeconds`   | NUMBER  | 否   | `5`                     | 轮询间隔（秒）                                    |
| `pollTimeoutSeconds`    | NUMBER  | 否   | `1800`                  | 轮询总超时（秒）                                  |
| `maxRetries`            | NUMBER  | 否   | `3`                     | 单次状态查询出现网络错误的最大重试次数            |

## AIG 接口数据结构

`GET /api/v1/app/taskapi/result/{id}` 的响应外层是统一的 `Envelope`，内层 `data` 直接是
AIG 的 `resultUpdate` 事件包装层（线上抓包确认），真正的扫描结果在 `data.result`：

```json
{
  "status": 0,
  "message": "ok",
  "data": {
    "id": "<uuid>",
    "type": "resultUpdate",
    "timestamp": 1778571245,
    "result": {
      "start_time": 1778570974.04,
      "end_time": 1778571245.39,
      "language": "Other",
      "llm": "kimi-k2.5",
      "readme": "## 信息收集报告 ...",
      "score": 60,
      "results": [
        {
          "title": "...",
          "description": "...",
          "level": "High",
          "risk_type": "...",
          "suggestion": "..."
        }
      ]
    }
  }
}
```

代码中对应的 Go 结构（`pkg/aig/types.go`）：

- `ResultData{ID, Type, Timestamp, Result}`：事件包装层。
- `ScanResult{StartTime, EndTime, Language, LLM, Readme, Score, Results}`：真正的扫描结果。
  - `StartTime` / `EndTime` 是带亚秒精度的浮点 Unix 时间戳。
  - `Score` 是 AIG 自带的 0–100 安全评分。
  - `Readme` 是 markdown 格式的总览，可能很长。
- `Issue{Title, Description, Level, RiskType, Suggestion}`：单条安全发现；
  线上 mcp_scan 响应中的 issue 只包含这五个字段，没有 `path` 字段
  （Path/PkgName 在 SecurityResult 中直接落到上传的压缩包名上）。

## 输出说明

- 每条 AIG `issue`（`data.result.results[*]`）输出一条 `SecurityResult`
- `VulId` 由 `sessionID + riskType + title + level` 派生为稳定 hash，并统一加 `aig-` 前缀
  （形如 `aig-<16 hex chars>`），便于在制品库漏洞表里区分 AIG 与其它扫描器（trivy / bandit ...）
- `Severity` 映射规则（大小写不敏感）：
  - `critical` / `malicious` → `critical`
  - `high` → `high`
  - `medium` / `suspicious` / `warning` → `medium`
  - `low` / `info` / 其他 → `low`
- `Des` = 从 `description` 中按 `### 技术分析` / `### 攻击路径` / `### 影响评估` 三段提取并拼接的子集（保留 `###` 标题、按文档原序、章节间空行分隔，统一剥离每行公共的前导缩进）；
  - 任意目标章节都解析不到时回退到原始 `description`，避免在文档格式变更后丢信息
  - `description` 为空时使用默认占位文本（与 `suggestion` 是否为空无关）
- `Solution` = `suggestion` 剥离开头的 `## 修复建议` 二级标题前缀、剥离正文公共前导缩进并 trim 后的结果，缺省时为空字符串，不强制占位
- `Path` = `description` 中 `**文件位置**` 行去掉 `/app/agent-scan/uploads/tmp-<id>/` 前缀后的相对路径（如 `skill-vul-test/SKILL.md`）；
  - `description` 中找不到 `**文件位置**` 时回退到上传的压缩包名 `fileName`
  - 兼容半角/全角冒号与前导空格
- `PkgName` = 上传的压缩包名 `fileName`（不随 `Path` 变化）
- 任务级元信息（`score` / `llm` / `language` / `readme` / 用时）不会塞进单条 `SecurityResult`，
  而是在 executor 层以 `Info` 日志输出，便于排查"为什么 issue=0 但 score≠100"等情况

## 本地构建

```bash
cd aig
go mod download
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o bkrepo-aig ./cmd/main.go
```

## 镜像构建

```bash
docker build -t bkrepo-aig:0.0.1 .
```

## 制品库 Admin 配置

由于本扫描器不附带 `tool.json`，需要在制品库 Admin 中手动添加为 `standard` 类型扫描器：

- **启动命令**：`/bkrepo-aig`
- **支持文件后缀**：`zip`
- **支持包类型**：`GENERIC`
- **支持扫描类型**：`SECURITY`
- **必填参数**：`baseUrl`、`modelName`、`modelToken`、`modelBaseUrl`
  - 缺 `baseUrl` / `modelName` / `modelToken` / `modelBaseUrl` 任一项，Execute 入口立刻返回 `missing required tool argument "<key>"`，不会触发任何上传/HTTP 调用
  - 即便绕过 Execute 直接构造 `aig.Client`，task 创建阶段也会被 `ErrMissingModelCredentials`（`missing required model fields: model/token/base_url must all be non-empty`）拦截
- **可选参数**：见上文「工具参数」表格
