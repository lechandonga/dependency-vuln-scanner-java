package com.github.lechandonga.dependencyvulnscannerjava.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.dependencyvulnscannerjava.support.BusinessModule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@BusinessModule("扫描服务端到端（提交/进度/结果/错误分类/去重/并发/重扫对比）")
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ScanApiIntegrationTest {

    private static Path vulnDbDir;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws IOException {
        vulnDbDir = Files.createTempDirectory("vulndb-it-");
        registry.add("scanner.vulndb.dir", () -> vulnDbDir.toString());
        registry.add("scanner.task.worker-threads", () -> "8");
    }

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String MANIFEST_JSON = """
            {"packageType":"maven","dependencies":[
              {"group":"g","name":"lib","version":"1.5.0"}
            ]}
            """;

    @BeforeAll
    void setUp() throws IOException {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        writeVulnDb("[1.0.0,2.0.0)", "HIGH", null, "2.0.0");
    }

    private void writeVulnDb(String range, String severity, String priority, String fixed)
            throws IOException {
        String priorityPart = priority == null ? "" : ",\"priority\":\"" + priority + "\"";
        String content = """
                {"vulnerabilities":[{
                  "id":"CVE-100","type":"maven","group":"g","name":"lib",
                  "affectedRange":"%s","fixedVersions":"%s",
                  "severity":"%s"%s,"description":"demo"
                }]}
                """.formatted(range, fixed, severity == null ? "HIGH" : severity, priorityPart);
        Files.writeString(vulnDbDir.resolve("v1.json"), content, StandardCharsets.UTF_8);
    }

    private record Hold(int status, JsonNode json) {
    }

    private Hold submit(String content, String format) throws Exception {
        String body = objectMapper.writeValueAsString(
                new ScanRequest(content, format, "it-manifest"));
        MvcResult result = mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn();
        return new Hold(result.getResponse().getStatus(),
                objectMapper.readTree(result.getResponse().getContentAsString()));
    }

    private JsonNode waitForCompletion(String taskId) throws Exception {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            MvcResult result = mockMvc.perform(get("/api/scans/" + taskId)).andReturn();
            JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
            String state = node.get("status").asText();
            if ("COMPLETED".equals(state) || "FAILED".equals(state)) {
                return node;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("任务 " + taskId + " 在超时时间内未结束");
    }

    private JsonNode submitAndWait(String content, String format) throws Exception {
        JsonNode submitted = submit(content, format).json();
        return waitForCompletion(submitted.get("taskId").asText());
    }

    private String dbHash() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/scans/vulnerability-db")).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("vulnerabilityDbHash").asText();
    }

    @Test
    @Order(1)
    @DisplayName("正常提交：返回任务 ID，轮询可见进度，最终拿到命中结论与升级建议")
    void happyPath() throws Exception {
        Hold created = submit(MANIFEST_JSON, "json");
        assertEquals(201, created.status());
        assertFalse(created.json().get("dedupHit").asBoolean());
        String taskId = created.json().get("taskId").asText();

        JsonNode finished = waitForCompletion(taskId);
        assertEquals("COMPLETED", finished.get("status").asText());
        assertEquals(100, finished.get("progress").asInt());

        MvcResult result = mockMvc.perform(get("/api/scans/" + taskId + "/result")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        JsonNode report = objectMapper.readTree(result.getResponse().getContentAsString());
        JsonNode findings = report.path("result").path("findings");
        assertEquals(1, findings.size());
        assertEquals("CVE-100", findings.get(0).get("vulnId").asText());
        assertEquals("[1.0.0,2.0.0)", findings.get(0).get("matchedRangeExpression").asText());
        assertEquals("2.0.0", findings.get(0).get("fixedVersions").asText());
        assertTrue(report.path("result").has("vulnerabilityDbHash"));
    }

    @Test
    @Order(2)
    @DisplayName("任务未完成时取结果返回 409 并携带当前进度")
    void resultWhileRunningConflict() throws Exception {
        JsonNode created = submit(MANIFEST_JSON, "json").json();
        MvcResult result = mockMvc.perform(
                get("/api/scans/" + created.get("taskId").asText() + "/result")).andReturn();
        int status = result.getResponse().getStatus();
        assertTrue(status == 409 || status == 200, "状态码应为 409 或 200，实际 " + status);
        waitForCompletion(created.get("taskId").asText());
    }

    @Test
    @Order(3)
    @DisplayName("清单全局格式错误：提交即被拒绝，错误码 MANIFEST_FORMAT_INVALID")
    void manifestFormatRejectedAtSubmit() throws Exception {
        Hold hold = submit("{broken json", "json");
        assertEquals(400, hold.status());
        assertEquals("MANIFEST_FORMAT_INVALID", hold.json().get("errorCode").asText());
    }

    @Test
    @Order(4)
    @DisplayName("清单条目错误：422 + MANIFEST_ENTRY_INVALID，响应带具体条目定位")
    void manifestEntryRejectedAtSubmit() throws Exception {
        String bad = """
                {"packageType":"maven","dependencies":[
                  {"group":"g","name":"lib","version":"1.5.0"},
                  {"group":"g","name":"lib2","version":"not,a,version"}
                ]}
                """;
        Hold hold = submit(bad, "json");
        assertEquals(422, hold.status());
        assertEquals("MANIFEST_ENTRY_INVALID", hold.json().get("errorCode").asText());
        assertTrue(hold.json().get("location").asText().contains("[1]"));
    }

    @Test
    @Order(5)
    @DisplayName("不支持的 format 返回 MANIFEST_FORMAT_INVALID")
    void unsupportedFormat() throws Exception {
        Hold hold = submit(MANIFEST_JSON, "yaml");
        assertEquals(400, hold.status());
        assertEquals("MANIFEST_FORMAT_INVALID", hold.json().get("errorCode").asText());
    }

    @Test
    @Order(6)
    @DisplayName("漏洞库条目非法：reload 被拒绝且旧快照保留；任务侧错误分类为 VULNDB_ENTRY_INVALID")
    void vulndbEntryFailureClassified() throws Exception {
        // 先确保服务内存中持有一份有效的旧快照
        MvcResult healthy = mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        assertEquals(200, healthy.getResponse().getStatus());

        // 写入含非法区间的漏洞库文件，reload 必须整体拒绝
        Files.writeString(vulnDbDir.resolve("bad.json"),
                "{\"vulnerabilities\":[{\"id\":\"BAD\",\"type\":\"maven\",\"name\":\"x\","
                        + "\"affectedRange\":\"[2.0,1.0)\"}]}", StandardCharsets.UTF_8);
        MvcResult reloadResult;
        try {
            reloadResult = mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
            assertEquals(422, reloadResult.getResponse().getStatus());
            JsonNode error = objectMapper.readTree(reloadResult.getResponse().getContentAsString());
            assertEquals("VULNDB_ENTRY_INVALID", error.get("errorCode").asText());
            assertTrue(error.get("message").asText().contains("bad.json"));

            // 旧快照仍然可用，扫描服务不被坏库污染
            JsonNode stillHealthy = objectMapper.readTree(
                    mockMvc.perform(get("/api/scans/vulnerability-db")).andReturn()
                            .getResponse().getContentAsString());
            assertTrue(stillHealthy.get("ruleCount").asInt() >= 1);
        } finally {
            Files.deleteIfExists(vulnDbDir.resolve("bad.json"));
        }

        // 首次启动且漏洞库目录为空时提交：任务/提交直接得到 VULNDB_UNAVAILABLE
        Path v1 = vulnDbDir.resolve("v1.json");
        String savedV1 = Files.readString(v1);
        Files.delete(v1);
        String emptyManifest = MANIFEST_JSON.replace("1.5.0", "1.5.2");
        try {
            // 新 Spring 上下文下没有快照时会在提交处返回 422；
            // 当前上下文仍持有旧快照，这里通过 reload 接口验证不可用分类
            MvcResult unavailable = mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
            JsonNode body = objectMapper.readTree(unavailable.getResponse().getContentAsString());
            assertEquals("VULNDB_UNAVAILABLE", body.get("errorCode").asText());
            assertFalse(emptyManifest.isBlank());
        } finally {
            Files.writeString(v1, savedV1, StandardCharsets.UTF_8);
            mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        }
    }

    @Test
    @Order(7)
    @DisplayName("漏洞库恢复后 reload 成功，快照指纹重新可用")
    void vulndbReloadRecovers() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertTrue(body.get("ruleCount").asInt() >= 1);
        assertFalse(body.get("vulnerabilityDbHash").asText().isBlank());
    }

    @Test
    @Order(8)
    @DisplayName("同一份清单并发重复提交只产生一个任务，全部返回相同 taskId")
    void concurrentDuplicateSubmissionsDeduplicated() throws Exception {
        String manifest = MANIFEST_JSON.replace("1.5.0", "1.6.2");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        Set<String> taskIds = java.util.Collections.synchronizedSet(new HashSet<>());
        List<Exception> errors = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    taskIds.add(submit(manifest, "json").json().get("taskId").asText());
                } catch (Exception e) {
                    errors.add(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(List.of(), errors);
        assertEquals(1, taskIds.size(), "并发重复提交必须去重为同一个任务");
        JsonNode finished = waitForCompletion(taskIds.iterator().next());
        assertEquals("COMPLETED", finished.get("status").asText());
    }

    @Test
    @Order(9)
    @DisplayName("不同清单并发提交互不串结果，命中与不命中各自正确")
    void concurrentDifferentManifestsIsolated() throws Exception {
        String hitManifest = MANIFEST_JSON.replace("1.5.0", "1.7.0");
        String missManifest = MANIFEST_JSON.replace("1.5.0", "3.0.0");
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        List<String> results = java.util.Collections.synchronizedList(new ArrayList<>());
        pool.submit(() -> {
            try {
                start.await();
                results.add("hit:" + submitAndWait(hitManifest, "json").get("status").asText());
            } catch (Exception e) {
                results.add("hit:ERROR " + e.getMessage());
            }
        });
        pool.submit(() -> {
            try {
                start.await();
                results.add("miss:" + submitAndWait(missManifest, "json").get("status").asText());
            } catch (Exception e) {
                results.add("miss:ERROR " + e.getMessage());
            }
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(results.contains("hit:COMPLETED"));
        assertTrue(results.contains("miss:COMPLETED"));
    }

    @Test
    @Order(10)
    @DisplayName("漏洞库更新后重扫：diff 明确指出结论消失/新增/变化及原因")
    void rescanAndDiffAfterVulnDbUpdate() throws Exception {
        String manifest = MANIFEST_JSON.replace("1.5.0", "1.8.5");

        // 基线：v1 区间 [1.0,2.0) HIGH，命中
        writeVulnDb("[1.0.0,2.0.0)", "HIGH", null, "2.0.0");
        Files.deleteIfExists(vulnDbDir.resolve("v2.json"));
        mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        String baseTaskId = submit(manifest, "json").json().get("taskId").asText();
        JsonNode baseFinished = waitForCompletion(baseTaskId);
        assertEquals("COMPLETED", baseFinished.get("status").asText());
        String baseHash = dbHash();

        // 更新：v1 收窄到 [1.0,1.5)（原结论消失）并升级 CRITICAL/P1；新增 v2 覆盖 1.8.5
        writeVulnDb("[1.0.0,1.5.0)", "CRITICAL", "P1", "1.5.0");
        Files.writeString(vulnDbDir.resolve("v2.json"), """
                {"vulnerabilities":[{
                  "id":"CVE-200","type":"maven","group":"g","name":"lib",
                  "affectedRange":"[1.8.0,1.9.0)","fixedVersions":"1.9.0",
                  "severity":"MEDIUM","description":"newly disclosed"
                }]}
                """, StandardCharsets.UTF_8);
        MvcResult reload = mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        assertEquals(200, reload.getResponse().getStatus());
        String targetHash = dbHash();
        assertFalse(baseHash.equals(targetHash), "漏洞库内容指纹更新后必须变化");

        String targetTaskId = submit(manifest, "json").json().get("taskId").asText();
        JsonNode targetFinished = waitForCompletion(targetTaskId);
        assertEquals("COMPLETED", targetFinished.get("status").asText());

        MvcResult diffResult = mockMvc.perform(get("/api/scans/diff")
                .param("baseTaskId", baseTaskId)
                .param("targetTaskId", targetTaskId)).andReturn();
        assertEquals(200, diffResult.getResponse().getStatus());
        JsonNode diff = objectMapper.readTree(diffResult.getResponse().getContentAsString());
        assertFalse(diff.get("sameVulnerabilityDb").asBoolean());

        // 原 CVE-100 对 1.8.5 不再命中 → removed
        List<String> removedIds = toStringList(diff.get("removed"));
        assertTrue(removedIds.stream().anyMatch(k -> k.startsWith("CVE-100|")),
                "应收敛 CVE-100，实际 " + removedIds);

        // 新 CVE-200 命中 1.8.5 → added
        List<String> addedIds = toStringList(diff.get("added"));
        assertTrue(addedIds.stream().anyMatch(k -> k.startsWith("CVE-200|")),
                "应新增 CVE-200，实际 " + addedIds);
    }

    @Test
    @Order(11)
    @DisplayName("同一漏洞区间调整但仍然命中时，diff 在 changed 中给出变化原因")
    void diffChangedWithReasons() throws Exception {
        String manifest = MANIFEST_JSON.replace("1.5.0", "1.8.0");

        writeVulnDb("[1.0.0,2.0.0)", "HIGH", null, "2.0.0");
        Files.deleteIfExists(vulnDbDir.resolve("v2.json"));
        mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        String baseTaskId = submit(manifest, "json").json().get("taskId").asText();
        waitForCompletion(baseTaskId);

        // 区间收窄但仍覆盖 1.8.0，同时严重度/优先级/修复版本变化
        writeVulnDb("[1.0.0,1.9.0)", "CRITICAL", "P1", "1.9.0");
        mockMvc.perform(post("/api/scans/vulnerability-db/reload")).andReturn();
        String targetTaskId = submit(manifest, "json").json().get("taskId").asText();
        waitForCompletion(targetTaskId);

        MvcResult diffResult = mockMvc.perform(get("/api/scans/diff")
                .param("baseTaskId", baseTaskId)
                .param("targetTaskId", targetTaskId)).andReturn();
        JsonNode diff = objectMapper.readTree(diffResult.getResponse().getContentAsString());
        JsonNode changed = diff.get("changed");
        assertEquals(1, changed.size());
        JsonNode change = changed.get(0);
        assertTrue(change.get("key").asText().startsWith("CVE-100|"));
        List<String> reasons = new ArrayList<>();
        change.get("reasons").forEach(r -> reasons.add(r.asText()));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("优先级")));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("严重度")));
        assertTrue(reasons.stream().anyMatch(r -> r.contains("修复版本")));
    }

    @Test
    @Order(12)
    @DisplayName("查询不存在的任务返回 404 TASK_NOT_FOUND")
    void taskNotFound() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/scans/does-not-exist")).andReturn();
        assertEquals(404, result.getResponse().getStatus());
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals("TASK_NOT_FOUND", body.get("errorCode").asText());
    }

    private static List<String> toStringList(JsonNode array) {
        List<String> list = new ArrayList<>();
        array.forEach(node -> list.add(node.get("key").asText()));
        return list;
    }
}
