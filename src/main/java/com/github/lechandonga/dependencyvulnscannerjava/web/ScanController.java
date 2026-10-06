package com.github.lechandonga.dependencyvulnscannerjava.web;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilityRepository;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilitySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.parser.FormatType;
import com.github.lechandonga.dependencyvulnscannerjava.parser.ManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.ParseException;
import com.github.lechandonga.dependencyvulnscannerjava.scanner.ReportDiff;
import com.github.lechandonga.dependencyvulnscannerjava.scanner.ReportDiffService;
import com.github.lechandonga.dependencyvulnscannerjava.scanner.ScanReport;
import com.github.lechandonga.dependencyvulnscannerjava.task.ScanManager;
import com.github.lechandonga.dependencyvulnscannerjava.task.ScanStatus;
import com.github.lechandonga.dependencyvulnscannerjava.task.ScanTask;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilityDatabaseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 扫描服务 REST 接口，全部为本地操作，不发起任何网络调用。
 */
@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ManifestParser manifestParser = new ManifestParser();
    private final ScanManager scanManager;
    private final VulnerabilityRepository repository;
    private final ReportDiffService diffService;

    public ScanController(ScanManager scanManager, VulnerabilityRepository repository,
                          ReportDiffService diffService) {
        this.scanManager = scanManager;
        this.repository = repository;
        this.diffService = diffService;
    }

    /** 提交一份依赖清单（清单原文随请求体提交，全部在本地解析）。 */
    @PostMapping
    public ResponseEntity<Map<String, Object>> submit(@RequestBody ScanRequest request) {
        if (request == null || request.content() == null || request.content().isBlank()) {
            throw new ApiException("MANIFEST_FORMAT_INVALID", "content 不能为空", HttpStatus.BAD_REQUEST);
        }
        if (request.format() == null || request.format().isBlank()) {
            throw new ApiException("MANIFEST_FORMAT_INVALID", "format 不能为空（json/xml/csv）",
                    HttpStatus.BAD_REQUEST);
        }
        final FormatType format;
        try {
            format = FormatType.fromName(request.format());
        } catch (IllegalArgumentException e) {
            throw new ApiException("MANIFEST_FORMAT_INVALID", e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        String manifestName = request.manifestName() == null || request.manifestName().isBlank()
                ? "manifest." + format.name().toLowerCase() : request.manifestName().trim();

        // 清单解析在提交线程同步完成：输入问题在提交时立即、明确地暴露，绝不进入任务队列
        List<Dependency> dependencies;
        try {
            dependencies = manifestParser.parse(request.content(), format, manifestName);
        } catch (ParseException e) {
            String code = e.isGlobal() ? "MANIFEST_FORMAT_INVALID" : "MANIFEST_ENTRY_INVALID";
            HttpStatus status = e.isGlobal() ? HttpStatus.BAD_REQUEST
                    : HttpStatus.UNPROCESSABLE_ENTITY;
            throw new ApiException(code, e.getMessage(), status, e.getLocation());
        }

        ScanManager.Submission submission;
        try {
            submission = scanManager.submit(dependencies, manifestName, request.content());
        } catch (VulnerabilityDatabaseException e) {
            throw new ApiException(e.getErrorCode(), e.getMessage(), HttpStatus.UNPROCESSABLE_ENTITY);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("taskId", submission.task().getTaskId());
        body.put("dedupHit", submission.dedupHit());
        body.put("manifestHash", submission.task().getManifestHash());
        body.put("status", submission.task().getStatus().name());
        body.put("createdAt", submission.task().getCreatedAt().toString());
        return ResponseEntity.status(submission.dedupHit() ? HttpStatus.OK : HttpStatus.CREATED).body(body);
    }

    /** 查询任务进度与结果（结果仅在 COMPLETED 时出现，失败只返回分类错误，不会出现半成品结果）。 */
    @GetMapping("/{taskId}")
    public Map<String, Object> status(@PathVariable String taskId) {
        ScanTask task = scanManager.getTask(taskId);
        return taskView(task, false);
    }

    /** 只取扫描结论；任务未完成时返回 409 并带当前进度。 */
    @GetMapping("/{taskId}/result")
    public ResponseEntity<Map<String, Object>> result(@PathVariable String taskId) {
        ScanTask task = scanManager.getTask(taskId);
        if (task.getStatus() == ScanStatus.COMPLETED) {
            return ResponseEntity.ok(taskView(task, true));
        }
        return ResponseEntity.status(HttpStatus.CONFLICT).body(taskView(task, false));
    }

    /**
     * 对比两次扫描（典型用法：漏洞库更新并 reload 后，用同一清单分别扫描，再调用本接口）。
     */
    @GetMapping("/diff")
    public Map<String, Object> diff(@RequestParam String baseTaskId, @RequestParam String targetTaskId) {
        ScanTask base = scanManager.getTask(baseTaskId);
        ScanTask target = scanManager.getTask(targetTaskId);
        if (base.getStatus() != ScanStatus.COMPLETED || target.getStatus() != ScanStatus.COMPLETED) {
            throw new ApiException("TASK_NOT_COMPLETED",
                    "参与对比的两个任务必须都是 COMPLETED 状态", HttpStatus.CONFLICT);
        }
        ScanReport baseReport = base.getReport();
        ScanReport targetReport = target.getReport();
        ReportDiff diff = diffService.diff(baseReport, baseTaskId, targetReport, targetTaskId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("baseTaskId", baseTaskId);
        body.put("targetTaskId", targetTaskId);
        body.put("baseDbHash", diff.baseDbHash());
        body.put("targetDbHash", diff.targetDbHash());
        body.put("sameVulnerabilityDb", diff.baseDbHash().equals(diff.targetDbHash()));
        body.put("added", diff.added());
        body.put("removed", diff.removed());
        body.put("changed", diff.changed());
        return body;
    }

    private Map<String, Object> taskView(ScanTask task, boolean withResult) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("taskId", task.getTaskId());
        body.put("manifestName", task.getManifestName());
        body.put("manifestHash", task.getManifestHash());
        body.put("status", task.getStatus().name());
        body.put("progress", task.getProgress());
        body.put("phase", task.getPhase());
        body.put("createdAt", task.getCreatedAt().toString());
        body.put("updatedAt", task.getUpdatedAt().toString());
        if (task.getStatus() == ScanStatus.FAILED) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("errorCode", task.getErrorCode());
            error.put("message", task.getErrorMessage());
            if (task.getErrorLocation() != null) {
                error.put("location", task.getErrorLocation());
            }
            body.put("error", error);
        }
        if (withResult && task.getStatus() == ScanStatus.COMPLETED) {
            ScanReport report = task.getReport();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("vulnerabilityDbHash", report.vulnerabilityDbHash());
            result.put("dependencyCount", report.dependencyCount());
            result.put("findingCount", report.findingCount());
            result.put("generatedAt", Instant.now().toString());
            result.put("findings", report.findings());
            body.put("result", result);
        }
        return body;
    }

    /** 手动重新装载本地漏洞库（漏洞库更新后调用，原子替换快照）。 */
    @PostMapping("/vulnerability-db/reload")
    public Map<String, Object> reloadDb() {
        try {
            VulnerabilitySnapshot snapshot = repository.reload();
            return Map.of(
                    "vulnerabilityDbHash", snapshot.contentHash(),
                    "loadedAt", snapshot.loadedAt().toString(),
                    "ruleCount", snapshot.rules().size(),
                    "sourceFiles", snapshot.sourceFiles());
        } catch (VulnerabilityDatabaseException e) {
            throw new ApiException(e.getErrorCode(), e.getMessage(),
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    /** 查看当前漏洞库快照信息。 */
    @GetMapping("/vulnerability-db")
    public Map<String, Object> currentDb() {
        try {
            VulnerabilitySnapshot snapshot = repository.currentSnapshot();
            return Map.of(
                    "vulnerabilityDbHash", snapshot.contentHash(),
                    "loadedAt", snapshot.loadedAt().toString(),
                    "ruleCount", snapshot.rules().size(),
                    "sourceFiles", snapshot.sourceFiles());
        } catch (VulnerabilityDatabaseException e) {
            throw new ApiException(e.getErrorCode(), e.getMessage(),
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }
}
