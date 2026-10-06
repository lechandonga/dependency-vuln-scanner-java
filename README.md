# 本地依赖漏洞扫描服务

一个完全离线运行的 Spring Boot 服务：提交依赖清单，服务用本地维护的漏洞库进行版本区间比对，
输出命中的漏洞、依赖版本和建议处理优先级。**不连接任何外部接口，也不会联网拉取数据。**

## 运行方式

```bash
# 离线构建与测试（依赖已在本地 Maven 仓库）
mvn -o test

# 启动（默认读取 data/vulnerability-db 下的漏洞库）
mvn -o spring-boot:run

# 指定固定端口（application.properties 中 server.port 默认 0=随机端口）
mvn -o spring-boot:run -Dspring-boot.run.arguments=--server.port=8080
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/scans` | 提交扫描任务（异步） |
| GET | `/api/scans/{taskId}` | 查询任务进度与结果 |
| GET | `/api/scans/{newId}/diff/{oldId}` | 对比同清单在两版漏洞库下的结论差异 |
| GET | `/api/library` | 查看当前漏洞库指纹、规则数、加载时间 |
| POST | `/api/library/reload` | 重新加载本地漏洞库目录 |

提交请求体（`content` 直传与 `filename` 本地读取二选一）：

```json
{
  "content": "{\"dependencies\":[{\"group\":\"org.x\",\"name\":\"a\",\"version\":\"1.2.3\"}]}",
  "format": "json"
}
```

```json
{ "filename": "sample-pom.xml", "format": "pom" }
```

响应：

```json
{ "taskId": "…", "reused": false, "statusUrl": "/api/scans/…" }
```

任务结果（终态 `SUCCEEDED`）包含 `findings`：漏洞编号、标题、坐标、命中版本、
命中的区间原文、严重程度、建议优先级（P0–P3）、修复建议；同时返回本次使用的
`libraryFingerprint`（漏洞库内容指纹）。

## 支持的清单格式

格式通过文件名后缀或请求中的 `format` 字段指定（`json` / `pom` / `text`）。

1. **JSON（`.json`）**

   ```json
   {
     "ecosystem": "maven",
     "dependencies": [
       {"group": "org.apache.commons", "name": "commons-lang3", "version": "3.12.0"}
     ]
   }
   ```
   顶层也可以直接是数组。生态缺省为 `maven`。

2. **Maven `pom.xml`（`.xml` / `pom`）**
   读取 `<dependencies>` 中的直接依赖；支持 `${project.version}`、`${revision}`
   等 pom 属性解析；`test` / `provided` scope 的依赖不参与扫描；无法解析的属性、
   缺少 version 的依赖会被逐条拒绝。

3. **文本锁文件（`.txt` / `.lock`）**，每行一条：

   ```text
   # 生态, group:name:version（生态可省略，默认 maven）
   maven,org.apache.commons:commons-lang3:3.12.0
   npm,lodash:4.17.20
   ```

## 支持的漏洞库格式

漏洞库为 `scanner.library-dir` 目录下的若干文件，按文件名排序后合并加载：

1. **JSON（`.json`）**

   ```json
   {
     "vulnerabilities": [
       {
         "id": "CVE-2021-0001",
         "ecosystem": "maven",
         "package": "org.apache.logging.log4j:log4j-core",
         "affectedVersions": "[2.0,2.17.0)",
         "severity": "critical",
         "priority": "P0",
         "title": "……",
         "recommendation": "升级到 2.17.0+"
       }
     ]
   }
   ```

2. **YAML（`.yaml` / `.yml`）**：字段与 JSON 完全一致，顶层 `vulnerabilities` 列表。
3. **文本/CSV（`.txt` / `.csv`）**，每行一条，`|` 分隔：

   ```text
   id|package(group:name)|affectedVersions|severity|priority|title|recommendation
   CVE-2019-0002|org.yaml:snakeyaml|[1.0,2.0)|high|P1|SnakeYaml 示例漏洞|升级到 2.0+
   ```

必填字段：`id`、包名（`package` 即 `group:name`，或分别给 `group`+`name`）、
`affectedVersions`。`severity` 支持 `critical/high/medium/low/unknown`（也接受中文
严重/高危/中危/低危）；`priority` 支持 `P0`–`P3`，缺省时按严重程度推导：
critical→P0、high→P1、medium/unknown→P2、low→P3。

## 版本号与区间规则

版本号按 `.`、`-`、`_` 切分，逐段按数值比较（`1.10 > 1.9`），缺省段按 0 处理
（`1.0 == 1.0.0`）；预发布限定词 `alpha < beta < milestone < rc < snapshot < 正式版`。

区间采用 Maven 风格语法：

| 写法 | 含义 |
| --- | --- |
| `[1.0,2.0)` | 含 1.0，不含 2.0 |
| `[1.0,2.0]` | 两端都含 |
| `(1.0,2.0)` | 两端都不含 |
| `[1.5]` | 精确版本（仅字面相同才命中，`1.5.0` 不命中） |
| `[2.0,)` / `(,1.0)` | 单侧区间 |
| `[1.0,1.5),[2.0,2.5)` | 并集，任一区间命中即可 |
| `*` | 命中所有版本 |

括号不配对、下界大于上界、边界版本非法、精确版本误用开括号等都会归为
`VERSION_RANGE_ERROR`。

## 匹配与去重

1. 按 `生态://group/name` 规范化坐标匹配，生态或坐标不同互不串结果。
2. 版本落入规则区间才算命中；匹配引擎为无状态纯函数，输入 + 库快照确定时输出确定。
3. **同一依赖版本对同一漏洞编号最多输出一条结论**：即使库中存在多条编号相同、
   区间重叠或区间为并集的规则，结论也不重复。
4. 不同漏洞编号即使区间重叠，也各自报告（确实是不同的漏洞）。
5. 清单内重复的 `坐标@版本` 先归一化；最终结论固定按
   `优先级 → 漏洞编号 → 坐标 → 版本` 排序，保证可复现。
6. 扫描期间漏洞库若被重新加载，进行中的任务仍使用自己拿到的不可变库快照。

## 可复现与重扫对比

每次成功加载漏洞库都会计算一个 SHA-256 内容指纹（规则按确定顺序序列化后计算），
扫描结果记录所用指纹。同一清单（内容 SHA-256 相同）+ 同一库指纹 ⇒ 结论完全一致。

漏洞库更新后对同一清单重扫，可用 `/api/scans/{newId}/diff/{oldId}` 对比，差异分类：

- `NEW_VULNERABILITY`：新库新增规则或区间扩大，给出新命中的版本与区间；
- `RESOLVED`：规则删除或区间收窄，旧命中不再成立；
- `RANGE_OR_SEVERITY_CHANGED`：仍命中，但区间/严重程度/优先级表达发生变化（附前后值）；
- 其余计入 `unchangedCount`。

## 解析问题与任务失败分类

**解析问题（清单与漏洞库共用同一分类，字段 `kind` 区分）：**

| kind | 含义 |
| --- | --- |
| `FILE_FORMAT_ERROR` | 整个文件格式损坏（非法 JSON/XML/YAML），无法逐条校验 |
| `ENTRY_FIELD_ERROR` | 条目级问题：必填字段缺失、版本号无法识别、severity/priority 非法等 |
| `VERSION_RANGE_ERROR` | 版本区间写法错误 |
| `DUPLICATE_RULE_ERROR` | 漏洞库内规则编号重复 |

默认 `scanner.reject-on-issue=true`：出现任何条目级问题都会**整体拒绝**并逐条返回
问题（带来源文件与条目序号/行号），绝不静默跳过。

**任务失败类型（`failureType`）：**

- `MANIFEST_ERROR`：清单问题，返回 4xx 语义与逐条 `issues`，调用方修改清单即可；
- `LIBRARY_ERROR`：漏洞库问题。重载失败时**保留旧快照**，已完成的旧任务结果仍可查，
  新扫描显式失败并附带库的问题清单；
- `SERVICE_ERROR`：服务自身异常（IO、内部错误），可重试。

失败任务状态固定为 `FAILED`，不携带任何半成品 `findings`。

## 并发、重复提交与任务生命周期

- 任务在独立工作线程池中执行，任务状态用 CAS 原子推进：
  `PENDING → RUNNING → SUCCEEDED / FAILED`。
- 相同清单内容（相同内容哈希）重复提交时复用既有未过期任务，响应中 `reused=true`，
  避免重复扫描和重复结果；不同清单并发提交各自隔离。
- 任务结果在内存中按 `scanner.task-ttl-seconds` 保留，默认 1 小时；超过保留期查询返回 404。
- 任务表默认上限 10000（`scanner.max-tasks`），超出淘汰最老任务。
- `stage` 字段可观察进度：解析清单 → 加载漏洞库（含库指纹前缀）→ 匹配 → 完成。

## 配置项（前缀 `scanner.*`）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `scanner.library-dir` | `data/vulnerability-db` | 本地漏洞库目录，仅读取，不联网 |
| `scanner.manifest-dir` | `data/manifests` | `filename` 方式允许访问的清单根目录（禁止路径穿越） |
| `scanner.reject-on-issue` | `true` | 存在解析问题时整体拒绝而非跳过 |
| `scanner.task-ttl-seconds` | `3600` | 任务结果保留秒数 |
| `scanner.max-tasks` | `10000` | 内存任务表上限 |
| `scanner.dedupe-same-content` | `true` | 相同清单内容重复提交是否复用任务 |

另有 `server.port`（默认 `0`，随机端口）。

## 测试

`mvn -o test` 运行全部 54 个用例。测试日志末尾的“业务测试报告”按业务模块汇总
覆盖情况（每个业务下的用例逐条打印 PASS/FAIL/SKIP）：

- 版本区间边界（开闭区间、并集、精确版本、非法区间）；
- 畸形输入分类拒绝（三种清单格式 + 三种漏洞库格式）；
- 匹配与去重（重叠区间、跨生态隔离、确定性输出、优先级推导）；
- 并发与重复提交（20 线程重复提交收敛为一个任务、不同任务结果隔离、三类失败原因）；
- 重扫差异（新增/消失/区间变化/完全可复现）；
- HTTP 接口端到端；
- 原有 Spring 上下文冒烟测试保持通过。
