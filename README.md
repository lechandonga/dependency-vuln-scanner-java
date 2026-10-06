# 本地依赖漏洞扫描服务（dependency-vuln-scanner-java）

一个完全本地运行的 Spring Boot 服务：提交一份依赖清单，服务用本地维护的漏洞库做版本区间比对，
输出命中的漏洞、命中的依赖与版本、以及建议的处理优先级。

**不发起任何网络请求**：清单与漏洞库均来自本地；除 Maven 构建期拉取依赖外，运行期不联网。

---

## 1. 快速开始

```bash
# 构建（JDK 21+，离线可用）
mvn -o clean package

# 启动（默认读取 ./vulndb 目录下的漏洞库，端口 8080）
java -jar target/dependency-vuln-scanner-java-1.0-SNAPSHOT.jar

# 提交一份清单扫描
curl -s -X POST http://localhost:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"format":"json","manifestName":"app.json","content":"{\"packageType\":\"maven\",\"dependencies\":[{\"group\":\"org.example\",\"name\":\"logging-core\",\"version\":\"1.3.0\"}]}"}'

# 查询进度与结果
curl -s http://localhost:8080/api/scans/{taskId}
curl -s http://localhost:8080/api/scans/{taskId}/result
```

工程自带样例：漏洞库见 `vulndb/sample-vulndb.json`，三种格式的清单样例见 `samples/`。

---

## 2. 支持的数据格式

清单与漏洞库都支持 **JSON、XML、CSV** 三种格式，解析后统一到内部模型
（`Dependency` / `VulnerabilityRule`），支持的包管理类型为 `maven`、`npm`、`pypi`。

### 2.1 依赖清单

**JSON**（根节点对象，依赖放在 `dependencies` 数组；包类型可写在根 `packageType` 或条目 `type`）：

```json
{
  "packageType": "maven",
  "dependencies": [
    {"group": "org.example", "name": "logging-core", "version": "1.2.3"},
    {"group": "", "name": "left-pad-lite", "version": "1.2.0", "type": "npm"}
  ]
}
```

**XML**：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest packageType="maven">
  <dependency>
    <group>org.example</group>
    <name>logging-core</name>
    <version>1.2.3</version>
  </dependency>
</manifest>
```

**CSV**（表头固定，首列起：`type,group,name,version`）：

```csv
type,group,name,version
maven,org.example,logging-core,1.2.3
npm,,left-pad-lite,1.2.0
```

必填字段：`name`、`version`、`type`（或根级默认包类型）；`group` 可空。

### 2.2 漏洞库

漏洞库是一个**目录**（配置项 `scanner.vulndb.dir`），目录下所有 `.json/.xml/.csv`
文件都会被读取并合并为一个不可变快照。单条规则字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 漏洞编号，全库唯一；重复编号整批装载被拒绝 |
| `type` | 是 | `maven` / `npm` / `pypi` |
| `name` | 是 | 受影响组件名 |
| `group` | 否 | 组织/命名空间；空或 `*` 表示匹配任意 group |
| `affectedRange` | 是 | 受影响版本区间，多个区间用 `\|` 分隔（并集） |
| `fixedVersions` | 否 | 已修复版本，`\|`、`,`、`;` 分隔，仅用于升级建议 |
| `severity` | 否 | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `cvss` | 否 | 0~10 的数值 |
| `priority` | 否 | 显式优先级 `P1`~`P4`，优先于 severity/cvss |
| `description` | 否 | 描述 |

JSON 示例：

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-0001",
      "type": "maven",
      "group": "org.example",
      "name": "logging-core",
      "affectedRange": "[1.0.0,1.4.2) | [1.5.0,1.5.2]",
      "fixedVersions": "1.4.2 | 1.5.2",
      "severity": "HIGH",
      "cvss": 7.5,
      "description": "远程代码执行"
    }
  ]
}
```

XML 用 `<vulndb><vulnerability>…</vulnerability></vulndb>`；CSV 表头为
`id,type,group,name,affectedRange,fixedVersions,severity,cvss,priority,description`。
XML 解析禁用 DOCTYPE 与外部实体（防 XXE）。

---

## 3. 版本号与版本区间规则

### 3.1 版本号

对标 Maven `ComparableVersion`，纯函数、确定性：

- `.`、`-`、`_`、`+` 均为分隔符；数字段按**数值**比较（`1.10 > 1.9`）；
- 末尾零被规整：`1` = `1.0` = `1.0.0`；
- 限定符顺序：
  `alpha(a) < beta(b) < milestone(m) < rc(cr) < snapshot < release(空/ga/final/release) < sp`，
  未知限定符按字典序排在 release 之前；
- 非法版本（空串、含空白、含逗号/括号等区间符号）被显式拒绝并报错。

### 3.2 版本区间（两种等价语法）

1. **Maven range（推荐）**
   - `[1.0,2.0)` 半开：含 1.0、不含 2.0；
   - `[1.0,2.0]` 闭区间；`(1.0,2.0)` 开区间；
   - `[1.0,)` 下界及以上；`(,2.0)` 上界以下；`[1.5]` 精确版本。
2. **简化比较表达式**：`>=1.0`、`>1.0`、`<=2.0`、`<2.0`、`=1.0`（或裸写 `1.0`），
   多个条件用逗号或分号连接表示交集，如 `>=1.0,<2.0`。

非法区间（括号不匹配、下界大于上界、`[1.0,1.0)` 这类空区间、区间内版本号非法等）
在解析/装载阶段就被拒绝，不会被静默跳过。

---

## 4. 匹配与去重规则（确定性、可解释）

- 漏洞库每次成功装载生成一个**不可变快照**，包含内容指纹 `vulnerabilityDbHash`
  （所有源文件名+内容的 SHA-256 前缀）。扫描结果绑定快照指纹。
- 规则按 `(type, name, vulnId)` 稳定排序后遍历，同输入同快照输出**字节级可复现**。
- 命中解释 `matchedRangeExpression` 给出具体命中的区间（如 `[1.0.0,1.4.2)`）。
- **去重键为 `(漏洞编号, 依赖坐标, 依赖版本)`**：一条依赖同时落进同一漏洞的多个
  重叠区间，只产生一条结论，命中解释取漏洞库中**声明的第一个命中区间**。
- 结果排序：`优先级 P1→P4 → severity → CVSS → 漏洞编号 → 依赖坐标`。
- **处理优先级推导**：显式 `priority` 优先；否则
  `CRITICAL→P1`、`HIGH→P2`、`MEDIUM→P3`、`LOW→P4`；
  severity 缺失时按 CVSS（≥9/≥7/≥4/其余）分档；都没有则 `P4`。

### 4.1 漏洞库更新后如何说清变化

1. 更新 `vulndb` 目录文件，调用 `POST /api/scans/vulnerability-db/reload` 原子替换快照；
   任一条目非法会**整体拒绝**并保留旧快照；
2. 对同一份清单重新提交扫描（去重键含快照指纹，更新后自动产生新任务）；
3. 调用 `GET /api/scans/diff?baseTaskId=..&targetTaskId=..`，得到：
   - `added`：新命中的漏洞及原因；
   - `removed`：不再命中的漏洞（区间收窄/规则移除）；
   - `changed`：仍命中但优先级/严重度/CVSS/命中区间/修复版本发生变化，逐条列出变化原因；
   - 并返回两次扫描各自的 `baseDbHash`/`targetDbHash` 与 `sameVulnerabilityDb`。

---

## 5. 任务并发与失败语义

- 清单在**提交线程同步解析**：输入问题在提交时立即返回，不进入任务队列；
  扫描在线程池异步执行，可随时轮询状态与进度（`QUEUED → RUNNING → COMPLETED/FAILED`）。
- 每个任务持有提交时固化的清单副本，任务之间不共享可变输入；
  结果或错误**一次性发布**，失败任务不会携带半成品结果。
- **重复提交去重**：去重键为 `清单内容哈希 + 漏洞库快照指纹`。
  同清单（且漏洞库未更新）在 QUEUED/RUNNING/COMPLETED 期间并发或重复提交，
  返回同一个 `taskId`（响应中 `dedupHit=true`），不产生重复结果；
  失败任务解除登记，允许修正后重新提交。

### 5.1 失败原因分类（errorCode）

| errorCode | 类别 | 典型场景 | 返回时机/HTTP |
| --- | --- | --- | --- |
| `MANIFEST_FORMAT_INVALID` | 清单问题 | JSON/XML 整体语法损坏、缺少根字段、格式不支持、CSV 表头/列数错误 | 提交即拒绝，400 |
| `MANIFEST_ENTRY_INVALID` | 清单问题 | 单条缺 `name/version/type`、版本号非法、包类型不支持（带条目/行号定位） | 提交即拒绝，422 |
| `VULNDB_UNAVAILABLE` | 漏洞库问题 | 目录不存在/无库文件/文件不可读 | reload 或提交，422；任务失败态同样携带 |
| `VULNDB_FORMAT_INVALID` | 漏洞库问题 | 库文件整体格式损坏 | 同上 |
| `VULNDB_ENTRY_INVALID` | 漏洞库问题 | 单条缺字段、区间写错、枚举非法、漏洞编号重复（带文件/条目定位） | 同上 |
| `INTERNAL_ERROR` | 服务自身问题 | 未预期异常 | 500 / 任务 FAILED |
| `TASK_NOT_FOUND` / `TASK_NOT_COMPLETED` | 查询问题 | 任务不存在 / 对比时任务未完成 | 404 / 409 |

所有错误响应结构统一：`timestamp / errorCode / message / location(可选)`。

---

## 6. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/scans` | 提交扫描。请求体 `{"content":"<清单原文>","format":"json|xml|csv","manifestName":"可选"}`；201 新建，200 命中去重 |
| `GET /api/scans/{taskId}` | 查询状态、进度百分比、阶段描述，及结果/错误 |
| `GET /api/scans/{taskId}/result` | 仅取结果；未完成返回 409 并带当前进度 |
| `GET /api/scans/diff?baseTaskId=&targetTaskId=` | 对比两次扫描结论差异 |
| `POST /api/scans/vulnerability-db/reload` | 重新装载本地漏洞库（原子替换快照） |
| `GET /api/scans/vulnerability-db` | 查看当前快照指纹、装载时间、规则数与来源文件 |

---

## 7. 配置项（`application.properties`，均可用环境变量覆盖）

| 配置项 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `server.port` | `SERVER_PORT` | `8080` | 服务端口 |
| `scanner.vulndb.dir` | `SCANNER_VULNDB_DIR` | `./vulndb` | 本地漏洞库目录（只读 `.json/.xml/.csv`） |
| `scanner.task.worker-threads` | `SCANNER_WORKER_THREADS` | `4` | 扫描任务工作线程数 |

---

## 8. 测试与业务覆盖日志

```bash
mvn -o test
```

共 71 个用例，全部通过（含工程原有的 `ApplicationTests`，未改动其语义）。
执行日志以“**业务模块 → 用例 → PASS/FAIL/跳过及原因**”的结构直接打印到控制台
（由 JUnit Platform `TestExecutionListener` 经 ServiceLoader 注册，
surefire 配置 `redirectTestOutputToFile=false`）。覆盖的业务模块：

- 版本号解析与比较（Maven 兼容、确定性）
- 版本区间解析与边界匹配（Maven range 与简化表达式、开闭边界、畸形区间）
- 依赖清单解析（三种格式归一；全局格式错误 vs 条目错误；XXE 拒绝）
- 漏洞库解析（区间并集、枚举/数值校验、重复区间/编号）
- 扫描引擎（重叠区间去重、确定性可复现、优先级推导与排序）
- 扫描服务端到端（提交/进度/结果、三类错误分类、16 并发重复提交去重、
  不同清单并发隔离、漏洞库更新后重扫 diff、404/409）

重点覆盖的场景类别：**畸形输入、版本区间边界、并发与重复提交**。
