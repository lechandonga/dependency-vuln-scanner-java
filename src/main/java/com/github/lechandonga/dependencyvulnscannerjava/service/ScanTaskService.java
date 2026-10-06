package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.config.ScannerProperties;
import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 扫描任务编排：
 * <ul>
 *   <li>任务在线程池中执行，互不共享可变状态；</li>
 *   <li>同一清单内容 + 同一库指纹的进行中/已完成任务复用，杜绝重复结果；</li>
 *   <li>状态用 CAS 原子推进，失败原因区分 MANIFEST/LIBRARY/SERVICE 三类；</li>
 *   <li>结果只在计算完成后一次性写入，绝不出现半成品结果。</li>
 * </ul>
 */
@Service
public class ScanTaskService {

    private static final Logger log = LoggerFactory.getLogger(ScanTaskService.class);

    private final ManifestService manifestService;
    private final VulnerabilityLibraryService libraryService;
    private final ScanEngine engine;
    private final ScannerProperties properties;

    private final Map<String, AtomicReference<ScanTask>> tasks = new ConcurrentHashMap<>();
    private final Map<String, String> contentIndex = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<String> insertionOrder = new ConcurrentLinkedDeque<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors()),
            runnable -> {
                Thread thread = new Thread(runnable, "scan-worker");
                thread.setDaemon(true);
                return thread;
            });

    public ScanTaskService(ManifestService manifestService,
                           VulnerabilityLibraryService libraryService,
                           ScanEngine engine,
                           ScannerProperties properties) {
        this.manifestService = manifestService;
        this.libraryService = libraryService;
        this.engine = engine;
        this.properties = properties;
    }

    public record SubmitResult(String taskId, boolean reused) {
    }

    public SubmitResult submit(String filename, String content, String format) {
        ManifestService.LoadedManifest manifest = manifestService.load(filename, content);
        String manifestHash = sha256(manifest.content());

        // 检查既有任务与创建新任务必须在同一把锁内完成，否则并发重复提交会各自建任务
        synchronized (this) {
            if (properties.isDedupeSameContent()) {
                String existingId = contentIndex.get(manifestHash);
                if (existingId != null) {
                    AtomicReference<ScanTask> existing = tasks.get(existingId);
                    if (existing != null && isUsable(existing.get())) {
                        return new SubmitResult(existingId, true);
                    }
                    contentIndex.remove(manifestHash, existingId);
                }
            }

            String id = UUID.randomUUID().toString();
            ScanTask created = new ScanTask(id, TaskStatus.PENDING, "已提交，等待解析清单",
                    manifestHash, null, 0, List.of(), null, null, List.of(),
                    System.currentTimeMillis(), System.currentTimeMillis());
            tasks.put(id, new AtomicReference<>(created));
            insertionOrder.add(id);
            if (properties.isDedupeSameContent()) {
                contentIndex.put(manifestHash, id);
            }
            evictIfNeeded();
            executor.submit(() -> run(id, manifest, format, manifestHash));
            return new SubmitResult(id, false);
        }
    }

    public ScanTask get(String id) {
        AtomicReference<ScanTask> ref = tasks.get(id);
        if (ref == null) {
            return null;
        }
        ScanTask task = ref.get();
        if (isExpired(task)) {
            return null;
        }
        return task;
    }

    private boolean isUsable(ScanTask task) {
        return task.status() != TaskStatus.FAILED && !isExpired(task);
    }

    private boolean isExpired(ScanTask task) {
        return (task.status() == TaskStatus.SUCCEEDED || task.status() == TaskStatus.FAILED)
                && System.currentTimeMillis() - task.updatedAt() > TimeUnit.SECONDS.toMillis(properties.getTaskTtlSeconds());
    }

    private void run(String id, ManifestService.LoadedManifest manifest, String format, String manifestHash) {
        AtomicReference<ScanTask> ref = tasks.get(id);
        try {
            advance(ref, TaskStatus.PENDING, TaskStatus.RUNNING, "正在解析清单",
                    null, null, null, null, null, null);

            List<Dependency> parsed;
            try {
                parsed = manifestService.parse(manifest, format);
            } catch (ManifestReadException e) {
                fail(ref, FailureType.MANIFEST_ERROR, e.getMessage(), e.issues());
                return;
            }
            List<Dependency> dependencies = engine.normalizeDependencies(parsed);
            advance(ref, TaskStatus.RUNNING, TaskStatus.RUNNING,
                    "清单解析完成（" + dependencies.size() + " 个依赖），正在加载漏洞库",
                    null, null, dependencies.size(), null, null, null);

            LibrarySnapshot snapshot;
            try {
                snapshot = libraryService.current();
            } catch (LibraryLoadException e) {
                fail(ref, FailureType.LIBRARY_ERROR, e.getMessage(), e.issues());
                return;
            } catch (RuntimeException e) {
                log.error("漏洞库加载异常", e);
                fail(ref, FailureType.SERVICE_ERROR, "漏洞库加载异常: " + e.getMessage(), List.of());
                return;
            }

            advance(ref, TaskStatus.RUNNING, TaskStatus.RUNNING,
                    "正在匹配漏洞（库指纹 " + snapshot.fingerprint().substring(0, 12) + "）",
                    null, snapshot.fingerprint(), null, null, null, null);

            List<Finding> findings = engine.scan(dependencies, snapshot);

            ScanTask prev = ref.get();
            ScanTask done = new ScanTask(id, TaskStatus.SUCCEEDED,
                    "扫描完成，命中 " + findings.size() + " 条",
                    manifestHash, snapshot.fingerprint(), dependencies.size(),
                    findings, null, null, List.of(),
                    prev.createdAt(), System.currentTimeMillis());
            if (!ref.compareAndSet(prev, done)) {
                log.warn("任务 {} 已被其他状态流转接管，丢弃结果", id);
            }
        } catch (RuntimeException e) {
            log.error("扫描任务内部异常: {}", id, e);
            fail(ref, FailureType.SERVICE_ERROR, "服务内部错误: " + e.getClass().getSimpleName(), List.of());
        }
    }

    private void fail(AtomicReference<ScanTask> ref, FailureType type, String message, List<Issue> issues) {
        ScanTask prev = ref.get();
        ScanTask failed = new ScanTask(prev.id(), TaskStatus.FAILED,
                "扫描失败: " + type,
                prev.manifestFingerprint(), prev.libraryFingerprint(), prev.dependencyCount(),
                List.of(), type, message, issues == null ? List.of() : issues,
                prev.createdAt(), System.currentTimeMillis());
        if (!ref.compareAndSet(prev, failed)) {
            log.warn("任务 {} 状态已变更，失败结果被忽略", prev.id());
        }
    }

    @SuppressWarnings("SameParameterValue")
    private void advance(AtomicReference<ScanTask> ref, TaskStatus expected, TaskStatus next, String stage,
                         List<Finding> findings, String libraryFingerprint, Integer dependencyCount,
                         FailureType failure, String message, List<Issue> issues) {
        ScanTask prev = ref.get();
        if (prev.status() != expected) {
            throw new IllegalStateException("任务状态不是 " + expected + "，当前 " + prev.status());
        }
        ScanTask updated = new ScanTask(prev.id(), next, stage,
                prev.manifestFingerprint(),
                libraryFingerprint != null ? libraryFingerprint : prev.libraryFingerprint(),
                dependencyCount != null ? dependencyCount : prev.dependencyCount(),
                findings != null ? findings : prev.findings(),
                failure, message, issues != null ? issues : prev.issues(),
                prev.createdAt(), System.currentTimeMillis());
        if (!ref.compareAndSet(prev, updated)) {
            throw new IllegalStateException("任务状态并发冲突");
        }
    }

    private void evictIfNeeded() {
        while (tasks.size() > properties.getMaxTasks()) {
            String oldest = insertionOrder.poll();
            if (oldest == null) {
                return;
            }
            AtomicReference<ScanTask> removed = tasks.remove(oldest);
            if (removed != null) {
                contentIndex.remove(removed.get().manifestFingerprint(), oldest);
            }
        }
    }

    private String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    @PreDestroy
    public void shutdown() {
        executor.shutdownNow();
    }
}
