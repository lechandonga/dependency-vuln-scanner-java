package com.github.lechandonga.dependencyvulnscannerjava.tests;

import com.github.lechandonga.dependencyvulnscannerjava.config.ScannerProperties;
import com.github.lechandonga.dependencyvulnscannerjava.service.FailureType;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanEngine;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanTask;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanTaskService;
import com.github.lechandonga.dependencyvulnscannerjava.service.TaskStatus;
import com.github.lechandonga.dependencyvulnscannerjava.service.VulnerabilityLibraryService;
import com.github.lechandonga.dependencyvulnscannerjava.service.ManifestService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：并发提交、重复提交去重、失败分类与任务隔离。 */
@DisplayName("业务：并发与重复提交")
class TaskConcurrencyTest {

    private ScannerProperties properties;
    private ManifestService manifestService;
    private VulnerabilityLibraryService libraryService;
    private ScanTaskService taskService;

    @BeforeEach
    void setUp(@TempDir Path tempDir) throws Exception {
        Path dbDir = tempDir.resolve("db");
        Path manifestDir = tempDir.resolve("manifests");
        Files.createDirectories(dbDir);
        Files.createDirectories(manifestDir);
        Files.writeString(dbDir.resolve("rules.json"), """
                {"vulnerabilities":[
                  {"id":"CVE-1","package":"g:a","affectedVersions":"[1.0,2.0)","severity":"high"}
                ]}
                """);
        properties = new ScannerProperties();
        properties.setLibraryDir(dbDir);
        properties.setManifestDir(manifestDir);
        manifestService = new ManifestService(properties);
        libraryService = new VulnerabilityLibraryService(properties);
        libraryService.init();
        taskService = new ScanTaskService(manifestService, libraryService, new ScanEngine(), properties);
    }

    @AfterEach
    void tearDown() {
        taskService.shutdown();
    }

    private static final String GOOD_MANIFEST =
            "{\"dependencies\":[{\"group\":\"g\",\"name\":\"a\",\"version\":\"1.5\"}]}";
    private static final String BAD_MANIFEST = "{dependencies: broken";

    @Test
    @DisplayName("相同清单内容并发重复提交只产生一个任务")
    void duplicateSubmissionsReuseTask() throws Exception {
        int threads = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        Set<String> taskIds = ConcurrentHashMap.newKeySet();
        List<Boolean> reusedFlags = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    ScanTaskService.SubmitResult result = taskService.submit(null, GOOD_MANIFEST, "json");
                    taskIds.add(result.taskId());
                    synchronized (reusedFlags) {
                        reusedFlags.add(result.reused());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(1, taskIds.size(), "重复提交必须收敛到同一个任务");
        assertEquals(threads - 1, reusedFlags.stream().filter(Boolean::booleanValue).count());

        String id = taskIds.iterator().next();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(TaskStatus.SUCCEEDED, taskService.get(id).status()));
        assertEquals(1, taskService.get(id).findings().size());
    }

    @Test
    @DisplayName("不同清单并发提交互不串结果")
    void concurrentDifferentManifestsIsolated() throws Exception {
        int count = 10;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(count);
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String manifest = "{\"dependencies\":[{\"group\":\"g\",\"name\":\"a\",\"version\":\""
                            + (idx % 2 == 0 ? "1.5" : "3.0") + "\"}]}";
                    synchronized (ids) {
                        ids.add(taskService.submit(null, manifest, "json").taskId());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(count, ids.stream().map(taskService::get).filter(t ->
                        t.status() == TaskStatus.SUCCEEDED).count()));
        long hit = ids.stream().map(taskService::get).filter(t -> t.findings().size() == 1).count();
        long clean = ids.stream().map(taskService::get).filter(t -> t.findings().isEmpty()).count();
        assertEquals(count / 2, hit);
        assertEquals(count / 2, clean);
    }

    @Test
    @DisplayName("清单畸形时任务失败并分类为 MANIFEST_ERROR，无半成品结果")
    void manifestFailureClassified() {
        String id = taskService.submit(null, BAD_MANIFEST, "json").taskId();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(TaskStatus.FAILED, taskService.get(id).status()));
        ScanTask task = taskService.get(id);
        assertEquals(FailureType.MANIFEST_ERROR, task.failureType());
        assertNotNull(task.failureMessage());
        assertFalse(task.issues().isEmpty());
        assertTrue(task.findings().isEmpty(), "失败任务不能携带半成品结果");
    }

    @Test
    @DisplayName("漏洞库损坏时新任务失败分类为 LIBRARY_ERROR，旧任务结果保持可读")
    void libraryFailureKeepsOldResults(@TempDir Path unused) throws Exception {
        String oldTaskId = taskService.submit(null, GOOD_MANIFEST, "json").taskId();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(TaskStatus.SUCCEEDED, taskService.get(oldTaskId).status()));
        String oldFingerprint = taskService.get(oldTaskId).libraryFingerprint();

        Files.writeString(properties.getLibraryDir().resolve("broken.json"),
                "{vulnerabilities: invalid");
        assertThrowsFromReload();

        // 注意：不能复用 GOOD_MANIFEST，否则会命中旧的成功任务去重索引
        String differentManifest =
                "{\"dependencies\":[{\"group\":\"g\",\"name\":\"a\",\"version\":\"1.6\"}]}";
        String newTaskId = taskService.submit(null, differentManifest, "json").taskId();
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(TaskStatus.FAILED, taskService.get(newTaskId).status()));
        assertEquals(FailureType.LIBRARY_ERROR, taskService.get(newTaskId).failureType());
        assertEquals(TaskStatus.SUCCEEDED, taskService.get(oldTaskId).status());
        assertEquals(oldFingerprint, taskService.get(oldTaskId).libraryFingerprint());
    }

    private void assertThrowsFromReload() {
        try {
            libraryService.reload();
            throw new AssertionError("损坏的库应导致 reload 抛异常");
        } catch (com.github.lechandonga.dependencyvulnscannerjava.service.LibraryLoadException expected) {
            // 预期：旧快照保留
        }
    }

    @Test
    @DisplayName("任务不存在或已过保留期时查询返回空")
    void missingTaskReturnsNull() {
        assertNull(taskService.get("non-existent-id"));
    }

    @Test
    @DisplayName("进度可查询：PENDING/RUNNING 到终态")
    void progressObservable() {
        String id = taskService.submit(null, GOOD_MANIFEST, "json").taskId();
        ScanTask task = taskService.get(id);
        assertNotNull(task.stage());
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertEquals(TaskStatus.SUCCEEDED, taskService.get(id).status()));
    }
}
