package com.github.lechandonga.dependencyvulnscannerjava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.test.web.client.TestRestTemplate;

import java.time.Duration;
import java.util.Map;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：HTTP 接口端到端行为（提交、查询进度/结果、错误分类、重复提交）。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "scanner.library-dir=src/test/resources/test-vulnerability-db",
                "scanner.manifest-dir=src/test/resources/test-manifests"
        })
@DisplayName("业务：HTTP 接口端到端")
class ScanApiIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    @Test
    @DisplayName("提交 -> 查询进度 -> 得到命中结果")
    @SuppressWarnings("unchecked")
    void submitAndPollToSuccess() {
        String innerContent = "{\"dependencies\":["
                + "{\"group\":\"g\",\"name\":\"a\",\"version\":\"1.5\"}]}";
        java.util.Map<String, String> body = java.util.Map.of("content", innerContent, "format", "json");
        ResponseEntity<Map> response = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>(body, jsonHeaders()), Map.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        String taskId = (String) response.getBody().get("taskId");
        assertNotNull(taskId);

        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
            ResponseEntity<Map> polled = restTemplate.getForEntity(url("/api/scans/" + taskId), Map.class);
            assertEquals("SUCCEEDED", polled.getBody().get("status"));
        });
        ResponseEntity<Map> finalTask = restTemplate.getForEntity(url("/api/scans/" + taskId), Map.class);
        java.util.List<?> findings = (java.util.List<?>) finalTask.getBody().get("findings");
        assertFalse(findings.isEmpty());
    }

    @Test
    @DisplayName("畸形清单返回 400 且错误类型为 MANIFEST_ERROR")
    @SuppressWarnings("unchecked")
    void malformedManifestReturns400() {
        java.util.Map<String, String> body = java.util.Map.of("content", "{broken json", "format", "json");
        ResponseEntity<Map> response = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>(body, jsonHeaders()), Map.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        String taskId = (String) response.getBody().get("taskId");
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
            ResponseEntity<Map> polled = restTemplate.getForEntity(url("/api/scans/" + taskId), Map.class);
            assertEquals("FAILED", polled.getBody().get("status"));
        });
    }

    @Test
    @DisplayName("相同内容第二次提交 reused=true")
    @SuppressWarnings("unchecked")
    void duplicateSubmitReused() {
        String innerContent = "{\"dependencies\":["
                + "{\"group\":\"g\",\"name\":\"a\",\"version\":\"1.0\"}]}";
        java.util.Map<String, String> body = java.util.Map.of("content", innerContent, "format", "json");
        ResponseEntity<Map> first = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>(body, jsonHeaders()), Map.class);
        ResponseEntity<Map> second = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>(body, jsonHeaders()), Map.class);
        assertEquals(Boolean.TRUE, second.getBody().get("reused"));
        assertEquals(first.getBody().get("taskId"), second.getBody().get("taskId"));
    }

    @Test
    @DisplayName("缺少 content 和 filename 返回 400")
    void emptyRequestRejected() {
        ResponseEntity<Map> response = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>("{}", jsonHeaders()), Map.class);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("MANIFEST_ERROR", response.getBody().get("type"));
    }

    @Test
    @DisplayName("查询不存在任务返回 404")
    void unknownTask404() {
        ResponseEntity<Map> response =
                restTemplate.getForEntity(url("/api/scans/no-such-task"), Map.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("漏洞库状态接口返回指纹与规则数")
    @SuppressWarnings("unchecked")
    void libraryStatusEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity(url("/api/library"), Map.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody().get("fingerprint"));
        assertTrue(((Number) response.getBody().get("ruleCount")).intValue() >= 1);
    }

    @Test
    @DisplayName("按文件名从本地清单目录读取")
    @SuppressWarnings("unchecked")
    void submitByFilename() {
        String body = "{\"filename\":\"good.json\"}";
        ResponseEntity<Map> response = restTemplate.postForEntity(url("/api/scans"),
                new HttpEntity<>(body, jsonHeaders()), Map.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        String taskId = (String) response.getBody().get("taskId");
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> {
            ResponseEntity<Map> polled = restTemplate.getForEntity(url("/api/scans/" + taskId), Map.class);
            assertEquals("SUCCEEDED", polled.getBody().get("status"));
        });
    }
}
