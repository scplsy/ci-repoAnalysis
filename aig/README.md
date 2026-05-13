## AIG Skill/MCP 扫描器

基于 [analysis-tool-sdk-golang](https://github.com/TencentBlueKing/ci-repoAnalysis/tree/master/analysis-tool-sdk-golang) 实现的蓝鲸制品库 standard 扫描器，对接 [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)，使用前需本地部署AI-Infra-Guard。

扫描器工作流程：

1. 上传待扫描的 MCP 源码 zip 包到 AIG（`POST /api/v1/app/taskapi/upload`）
2. 创建 `mcp_scan` 类型的任务（`POST /api/v1/app/taskapi/tasks`）
3. 周期轮询任务状态（`GET /api/v1/app/taskapi/status/{id}`）
4. 任务完成后拉取扫描结果（`GET /api/v1/app/taskapi/result/{id}`）
5. 把每条 result 转换为 `SecurityResult` 输出

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

- **启动命令**：`/bkrepo-aig`
- **支持文件后缀**：`zip`
- **支持包类型**：`GENERIC`
- **支持扫描类型**：`SECURITY`
- **参数**：

| 参数名                    | 类型     | 必填 | 默认值    | 说明                                                             |
|------------------------|--------|----|--------|----------------------------------------------------------------|
| `modelName`            | STRING | 是  | -      | LLM 模型名（例如 `gpt-4`、`deepseek-chat`、`kimi-k2.5`）                |
| `modelToken`           | STRING | 是  | -      | LLM API key                                                    |
| `modelBaseUrl`         | STRING | 是  | -      | LLM API base URL，例如https://api.lkeap.cloud.tencent.com/plan/v3 |
| `baseUrl`              | STRING | 是  | -      | 本地部署的AIG 服务接入地址，例如http://localhost:8088                        |
| `prompt`               | STRING | 否  | -      | 附加的扫描提示词                                                       |
| `language`             | STRING | 否  | `zh`   | AIG 输出语言（`zh` / `en`）                                          |
| `thread`               | NUMBER | 否  | `4`    | AIG 后端并发线程数                                                    |
| `uploadTimeoutSeconds` | NUMBER | 否  | `300`  | 单次上传请求超时（秒）                                                    |
| `pollIntervalSeconds`  | NUMBER | 否  | `5`    | 轮询间隔（秒）                                                        |
| `pollTimeoutSeconds`   | NUMBER | 否  | `1800` | 轮询总超时（秒）                                                       |
| `maxRetries`           | NUMBER | 否  | `3`    | 单次状态查询出现网络错误的最大重试次数                                            |
