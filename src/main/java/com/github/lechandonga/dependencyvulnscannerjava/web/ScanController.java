package com.github.lechandonga.dependencyvulnscannerjava.web;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;
import com.github.lechandonga.dependencyvulnscannerjava.service.LibraryLoadException;
import com.github.lechandonga.dependencyvulnscannerjava.service.ManifestReadException;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanDiffService;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanTask;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanTaskService;
import com.github.lechandonga.dependencyvulnscannerjava.web.dto.ErrorResponse;
import com.github.lechandonga.dependencyvulnscannerjava.web.dto.ScanRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanTaskService taskService;
    private final ScanDiffService diffService;

    public ScanController(ScanTaskService taskService, ScanDiffService diffService) {
        this.taskService = taskService;
        this.diffService = diffService;
    }

    /** 提交扫描任务；重复提交同内容清单时复用既有任务（reused=true）。 */
    @PostMapping
    public Map<String, Object> submit(@RequestBody(required = false) ScanRequest request) {
        if (request == null || ((request.content() == null || request.content().isEmpty())
                && (request.filename() == null || request.filename().isBlank()))) {
            throw new ManifestReadException("请求体必须包含 content 或 filename", java.util.List.of());
        }
        ScanTaskService.SubmitResult result =
                taskService.submit(request.filename(), request.content(), request.format());
        return Map.of("taskId", result.taskId(), "reused", result.reused(),
                "statusUrl", "/api/scans/" + result.taskId());
    }

    /** 查询任务进度与结果；终态后超过保留期返回 404。 */
    @GetMapping("/{id}")
    public ScanTask get(@PathVariable String id) {
        ScanTask task = taskService.get(id);
        if (task == null) {
            throw new TaskNotFoundException(id);
        }
        return task;
    }

    /** 对比同清单在两版漏洞库下的扫描结论。 */
    @GetMapping("/{newId}/diff/{oldId}")
    public ScanDiffService.DiffResult diff(@PathVariable String newId, @PathVariable String oldId) {
        ScanTask newTask = taskService.get(newId);
        ScanTask oldTask = taskService.get(oldId);
        if (newTask == null || oldTask == null) {
            throw new TaskNotFoundException(newTask == null ? newId : oldId);
        }
        return diffService.diff(oldTask, newTask);
    }

    @ExceptionHandler(ManifestReadException.class)
    public ResponseEntity<ErrorResponse> handleManifest(ManifestReadException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse(
                "MANIFEST_ERROR", "MANIFEST_ERROR", e.getMessage(), e.issues()));
    }

    @ExceptionHandler(LibraryLoadException.class)
    public ResponseEntity<ErrorResponse> handleLibrary(LibraryLoadException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse(
                "LIBRARY_ERROR", "LIBRARY_ERROR", e.getMessage(), e.issues()));
    }

    @ExceptionHandler(TaskNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(TaskNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(
                "NOT_FOUND", "SERVICE_ERROR", e.getMessage(), java.util.List.of()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(new ErrorResponse(
                "BAD_REQUEST", "SERVICE_ERROR", e.getMessage(),
                java.util.List.<Issue>of()));
    }

    static class TaskNotFoundException extends RuntimeException {
        TaskNotFoundException(String id) {
            super("任务不存在或结果已过期: " + id);
        }
    }
}
