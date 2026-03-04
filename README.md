# trace

trace 是一个面向安全运营的阿里云 WAF 日志分析工具，聚焦两件事：

1. 资产发现：从访问日志中提取可达资产 URL，形成可排序清单。
2. 未授权测试：自动构建候选目标并输出规则化风险判断。

## 核心特点

- 双主线输出：`assets.csv` + `unauth_targets.csv`。
- 配置优先：阈值、词库、正则、过滤策略都在 `trace.toml`。
- 降噪完整链路：后缀黑名单、路径模板归一化、Query 脱敏。
- 风险可解释：输出 `RISK_LEVEL / SCORE / REASONS`。
- 工程化可扩展：数据源解耦（`RowSource`），可扩展 CSV 以外来源。
- 高质量探测：同类目标去重与 TopN 收敛，避免对相似项重复发包，降低对业务系统的探测压力。
- 路径资产优化：资产收集不是只看域名，而是围绕“带路径资产”做聚合、排序和可达性验证。

## 高级能力

### 路径模板归一化

trace 会把高频动态路径自动收敛为稳定模板，例如：

- `/api/order/123456` -> `/api/order/{int}`
- `/user/550e8400-e29b-41d4-a716-446655440000` -> `/user/{uuid}`
- `/task/a3f9c1d8e4aa92bc` -> `/task/{hex}`

这不是简单替换，而是在做一层“路径语义压缩”：

- 降低同一接口因 ID、UUID、哈希值不同造成的重复膨胀
- 让未授权候选更接近真实接口面，而不是海量一次性 URL
- 让 TopN 保留、频次排序、人工复核都更稳定

对于日志驱动的接口挖掘来说，这一步本质上是在把“访问痕迹”转换成“接口轮廓”。

### Query 脱敏

trace 支持对 `request_uri` 中的 Query 参数进行脱敏输出，避免候选 URL 在导出、共享、复测时携带敏感值。

支持两种模式：

- 全量脱敏：所有参数值统一抹除
- 精准脱敏：仅对 `token`、`sign`、`session`、`password`、`cookie` 等敏感参数脱敏

它的价值不只是“隐藏字符串”，而是降低两个现实风险：

- 降低导出结果中泄露认证信息、签名串、会话标识的概率
- 降低直接复测原始 URL 时因敏感参数仍然有效而产生误判的概率

这样导出的目标更适合流转、归档和二次验证。

### 风险建模

trace 的未授权识别不是单一规则命中，而是一个可配置的轻量规则引擎。

它会综合多个信号打分：

- HTTP 状态码
- JSON / HTML 响应形态
- 登录页 / 认证特征
- 敏感关键词与敏感正则
- 业务字段与业务正则
- API / 管理路径特征
- 噪声关键词与噪声正则

最终输出：

- `RISK_LEVEL`
- `SCORE`
- `REASONS`

这意味着它不仅告诉你“像不像问题”，还告诉你“为什么像问题”。  
对于批量筛选场景，这种可解释性比单纯的命中/未命中更适合进入人工研判和运营闭环。

### 精准探测策略

trace 在未授权目标阶段会先做去重与收敛，再决定探测集合，而不是对日志中每条 URL 直接发包：

- 同一 `scheme + host + port + path` 支持按频次 TopN 保留代表性 URI
- 路径模板归一化减少“同接口不同 ID”导致的重复探测
- Query 脱敏降低无效参数差异引发的目标膨胀
- 仅对 GET 目标执行未授权探测，避免对写操作链路产生额外扰动

整体策略是“低扰动优先”：通过只测 GET + 参数脱敏 + 去重收敛，在覆盖核心暴露面的同时，最大程度降低对生产系统业务行为的影响。

### 路径资产视角

trace 的资产视角是“可访问路径资产”，不是纯主机清单：

- 以 `scheme + host + port + 一级路径` 做资产聚合
- 目录型路径默认聚合为 `/xx/`（例如 `/xx/login.jsp` -> `/xx/`）
- 单段文件型路径（如 `/ad_display.jspx`）可通过配置直接跳过
- 对聚合结果做频次排序，优先暴露高活跃路径面
- 可选主动探测补齐 `STATUS_CODE / TITLE`，便于快速研判可达性与服务特征
- 同一 `scheme + host + port` 下，若 `status_code + body_hash` 一致，自动折叠为单条代表资产（优先保留 `/`）

这让输出结果更接近真实暴露面，而不只是基础域名/IP 枚举结果。

示例（去重前 -> 去重后）：

```text
输入候选（同站点）:
https://www.aa.com/xx/login.jsp   status=200  body_hash=abc
https://www.aa.com/xx/index.jsp   status=200  body_hash=abc
https://www.aa.com/               status=200  body_hash=abc

输出资产:
https://www.aa.com/               COUNT=三者合计
```

## 项目结构

```text
src/
  main.rs
  asset/
    mod.rs
    analyzer.rs
    probe.rs
  unauth/
    mod.rs
    scan.rs
    intel.rs
  common/
    mod.rs
    config.rs
    output.rs
    source.rs
    source_csv.rs
```

说明：
- `asset`：资产聚合与主动探测。
- `unauth`：未授权候选构建与智能识别。
- `common`：配置、输出、数据源抽象与 CSV 实现。

## 快速开始

### 1) 准备配置

默认读取当前目录 `trace.toml`。

### 2) 运行

```bash
# 常规运行
trace test.csv

# 指定配置 + 输出格式
trace -c trace.toml -f both test.csv

# 指定输出目录
trace -o out test.csv
```

## CLI 参数

```text
 .\trace.exe -h

+=================================================================================================================================+
|       /\__                                                                                                                      |
|       (    @\___                                                                                                                |
|       /         O                                TRACR WAF日志分析工具(资产收集与未授权漏洞测试)                                |
|       /   (_____/                                            Powered by 基建运维中心                                            |
|       /_____/   U                                                                                                               |
+=================================================================================================================================+
Usage: trace [OPTIONS] [CSV]

Arguments:
  [CSV]  输入 CSV 日志路径。

Options:
  -c, --config <TOML>    配置文件路径（不存在则使用默认配置）。 [default: trace.toml]
  -f, --format <FORMAT>  覆盖输出格式：csv | json | both。
  -o, --out-dir <DIR>    覆盖输出目录。
  -h, --help             显示帮助信息。
```

行为说明：
- 不带参数运行：显示 banner + usage（不报错退出）。
- `-h/--help`：显示 banner + 完整帮助。

## 输出文件

### assets.csv

- `HOST`
- `PORT`
- `URL`
- `COUNT`
- `STATUS_CODE`
- `TITLE`

### unauth_targets.csv

- `HOST`
- `PORT`
- `PATH`
- `URL`
- `COUNT`
- `STATUS_CODE`
- `TITLE`
- `RISK_LEVEL`
- `SCORE`
- `REASONS`

## 关键配置块

- `[filter]`：公共过滤（状态码区间、后缀黑名单）
- `[web_request]`：探测并发、超时、UA、响应读取上限
- `[asset]` / `[asset_probe]`：资产聚合与探测行为
- `[asset_path]`：资产路径聚合策略（目录尾斜杠、单段文件型跳过）
- `[unauth_probe]`：未授权目标筛选、脱敏、TopN
- `[unauth_intel]`：关键词/正则规则引擎与打分阈值
- `[path_normalization]`：`{int}/{uuid}/{hex}` 路径归一化
- `[output]`：输出格式、目录、颜色、展示条数

## 匹配规则说明（后缀黑名单）

当前为路径后缀匹配，不是中间包含匹配：

- 命中条件：`path.ends_with(suffix)` 或 `path.ends_with("." + suffix)`
- 例如配置 `.jpg/show`，仅路径结尾为 `.jpg/show` 才会命中

## 注意事项

- 本工具会对候选 URL 发起主动请求（取决于 `asset_probe.enabled` 和 `unauth_probe.enabled`）。
- 若你处理敏感参数，建议启用 `unauth_probe.redact_query_values = true`。


