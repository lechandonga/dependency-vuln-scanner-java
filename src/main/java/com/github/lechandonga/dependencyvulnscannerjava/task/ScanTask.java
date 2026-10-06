package com.github.lechandonga.dependencyvulnscannerjava.task;

import com.github.lechandonga.dependencyvulnscannerjava.scanner.ScanReport;

import java.time.Instant;
import java.util.List;

/**
 * 扫描任务的不可变视图。任务内部状态用同步块保护，
 * 只有 {@code COMPLETED + report} 或 {@code FAILED + error} 会一次性对外发布。
 */
public class ScanTask {

    private final String taskId;
    private final String manifestHash;
    private final String manifestName;
    private final String dedupKey;

    private ScanStatus status = ScanStatus.QUEUED;
    private int progress = 0;
    private String phase = "已提交";
    private ScanReport report;
    private String errorCode;
    private String errorMessage;
    private String errorLocation;
    private final Instant createdAt = Instant.now();
    private Instant updatedAt = createdAt;

    ScanTask(String taskId, String manifestHash, String manifestName, String dedupKey) {
        this.taskId = taskId;
        this.manifestHash = manifestHash;
        this.manifestName = manifestName;
        this.dedupKey = dedupKey;
    }

    public String getTaskId() {
        return taskId;
    }

    public String getManifestHash() {
        return manifestHash;
    }

    public String getManifestName() {
        return manifestName;
    }

    public String getDedupKey() {
        return dedupKey;
    }

    public synchronized ScanStatus getStatus() {
        return status;
    }

    public synchronized int getProgress() {
        return progress;
    }

    public synchronized String getPhase() {
        return phase;
    }

    public synchronized ScanReport getReport() {
        return report;
    }

    public synchronized String getErrorCode() {
        return errorCode;
    }

    public synchronized String getErrorMessage() {
        return errorMessage;
    }

    public synchronized String getErrorLocation() {
        return errorLocation;
    }

    public synchronized Instant getCreatedAt() {
        return createdAt;
    }

    public synchronized Instant getUpdatedAt() {
        return updatedAt;
    }

    synchronized void markRunning(String phaseText) {
        this.status = ScanStatus.RUNNING;
        this.progress = 10;
        this.phase = phaseText;
        this.updatedAt = Instant.now();
    }

    synchronized void updateProgress(int percent, String phaseText) {
        this.progress = percent;
        this.phase = phaseText;
        this.updatedAt = Instant.now();
    }

    synchronized void complete(ScanReport scanReport) {
        this.status = ScanStatus.COMPLETED;
        this.progress = 100;
        this.phase = "完成";
        this.report = scanReport;
        this.updatedAt = Instant.now();
        this.notifyAll();
    }

    synchronized void fail(String code, String message, String location) {
        this.status = ScanStatus.FAILED;
        this.phase = "失败";
        this.errorCode = code;
        this.errorMessage = message;
        this.errorLocation = location;
        this.report = null;
        this.updatedAt = Instant.now();
        this.notifyAll();
    }

    public synchronized boolean isResolved() {
        return status == ScanStatus.COMPLETED || status == ScanStatus.FAILED;
    }

    public synchronized List<String> snapshotErrors() {
        if (errorCode == null) {
            return List.of();
        }
        return List.of(errorCode, errorMessage == null ? "" : errorMessage,
                errorLocation == null ? "" : errorLocation);
    }
}
