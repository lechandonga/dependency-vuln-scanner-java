package com.github.lechandonga.dependencyvulnscannerjava.task;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilityDatabaseException;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilityRepository;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilitySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.scanner.ScanReport;
import com.github.lechandonga.dependencyvulnscannerjava.scanner.ScannerEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描任务调度中心：
 * <ul>
 *   <li>清单在提交时同步解析并固化到任务，任务之间不共享可变输入；</li>
 *   <li>同一份清单（内容哈希相同）在 QUEUED/RUNNING/COMPLETED 期间重复提交，
 *       直接复用原任务，不产生重复结果；FAILED 后允许重新提交并生成新任务；</li>
   <li>任务在独立线程池执行，结果或错误一次性发布，半成品对外不可见；</li>
 *   <li>执行期错误被归类为清单问题 / 漏洞库问题 / 服务自身问题。</li>
 * </ul>
 */
@Component
public class ScanManager implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ScanManager.class);

    private final VulnerabilityRepository repository;
    private final ScannerEngine engine;
    private final ExecutorService executor;

    private final Map<String, ScanTask> tasks = new ConcurrentHashMap<>();
    /** dedupKey → taskId，仅登记未失败的任务。 */
    private final Map<String, String> activeByDedupKey = new ConcurrentHashMap<>();

    public ScanManager(VulnerabilityRepository repository, ScannerEngine engine,
                       @Value("${scanner.task.worker-threads:4}") int workerThreads) {
        this.repository = repository;
        this.engine = engine;
        AtomicInteger counter = new AtomicInteger();
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "scan-worker-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        this.executor = Executors.newFixedThreadPool(Math.max(1, workerThreads), factory);
    }

    /**
     * 提交扫描。清单已经在外部解析通过，这里只做登记与调度。
     *
     * @return 任务对象；dedupHit 为 true 表示复用了已有任务
     */
    public Submission submit(List<Dependency> dependencies, String manifestName, String manifestRaw) {
        // 漏洞库问题在提交阶段即可暴露（与清单问题一样在提交时拒绝/分类），
        // 同时把快照指纹纳入去重键：漏洞库更新后同清单重扫会产生新任务
        VulnerabilitySnapshot snapshot;
        try {
            snapshot = repository.currentSnapshot();
        } catch (VulnerabilityDatabaseException e) {
            throw e;
        }
        String manifestHash = sha256Prefix(manifestRaw);
        String dedupKey = manifestHash + "|" + snapshot.contentHash();

        // 双重检查 + 创建原子化，保证并发重复提交只创建一个任务
        String existingId = activeByDedupKey.get(dedupKey);
        if (existingId != null) {
            ScanTask existing = tasks.get(existingId);
            if (existing != null && existing.getStatus() != ScanStatus.FAILED) {
                return new Submission(existing, true);
            }
        }
        synchronized (this) {
            String racedId = activeByDedupKey.get(dedupKey);
            if (racedId != null) {
                ScanTask raced = tasks.get(racedId);
                if (raced != null && raced.getStatus() != ScanStatus.FAILED) {
                    return new Submission(raced, true);
                }
            }
            String taskId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            ScanTask task = new ScanTask(taskId, manifestHash, manifestName, dedupKey);
            tasks.put(taskId, task);
            activeByDedupKey.put(dedupKey, taskId);
            executor.submit(() -> run(task, dependencies));
            return new Submission(task, false);
        }
    }

    private void run(ScanTask task, List<Dependency> dependencies) {
        try {
            task.markRunning("装载本地漏洞库快照");
            VulnerabilitySnapshot snapshot = repository.currentSnapshot();
            task.updateProgress(40, "漏洞库快照 " + snapshot.contentHash() + "，规则 "
                    + snapshot.rules().size() + " 条，开始版本匹配");
            ScanReport report = engine.scan(dependencies, snapshot);
            task.updateProgress(90, "匹配完成，发布结果");
            task.complete(report);
        } catch (VulnerabilityDatabaseException e) {
            log.warn("任务 {} 因漏洞库问题失败: {}", task.getTaskId(), e.getMessage());
            task.fail(e.getErrorCode(), e.getMessage(), null);
        } catch (RuntimeException e) {
            log.error("任务 {} 发生服务内部错误", task.getTaskId(), e);
            task.fail("INTERNAL_ERROR", "服务内部错误: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage(), null);
        } finally {
            // 失败任务解除去重登记，允许调用方修正后重新提交
            if (task.getStatus() == ScanStatus.FAILED) {
                activeByDedupKey.remove(task.getDedupKey(), task.getTaskId());
            }
        }
    }

    public ScanTask getTask(String taskId) {
        ScanTask task = tasks.get(taskId);
        if (task == null) {
            throw new TaskNotFoundException(taskId);
        }
        return task;
    }

    @Override
    public void destroy() {
        executor.shutdownNow();
    }

    private static String sha256Prefix(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content.getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    public record Submission(ScanTask task, boolean dedupHit) {
    }
}
