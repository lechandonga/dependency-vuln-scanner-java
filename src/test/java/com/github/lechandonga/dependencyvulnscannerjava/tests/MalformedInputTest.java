package com.github.lechandonga.dependencyvulnscannerjava.tests;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.VulnerabilityRule;
import com.github.lechandonga.dependencyvulnscannerjava.parser.IssueKinds;
import com.github.lechandonga.dependencyvulnscannerjava.parser.JsonManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.JsonVulnerabilityLibraryParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.ParseOutcome;
import com.github.lechandonga.dependencyvulnscannerjava.parser.PomManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.TextManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.TextVulnerabilityLibraryParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.YamlVulnerabilityLibraryParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：畸形输入分类拒绝（文件格式 / 条目字段 / 版本区间三类可区分）。 */
@DisplayName("业务：畸形输入分类拒绝")
class MalformedInputTest {

    @Nested
    @DisplayName("JSON 清单")
    class JsonManifest {

        @Test
        @DisplayName("整体 JSON 损坏 -> FILE_FORMAT_ERROR 且无条目产出")
        void brokenJson() {
            ParseOutcome<Dependency> outcome = new JsonManifestParser()
                    .parse("{dependencies: [}", "bad.json");
            assertTrue(outcome.fatal());
            assertEquals(IssueKinds.FILE_FORMAT_ERROR, outcome.issues().get(0).kind());
            assertTrue(outcome.items().isEmpty());
        }

        @Test
        @DisplayName("单条缺 name、另一条缺 version -> ENTRY_FIELD_ERROR，好条目保留")
        void missingFields() {
            String json = "{\"dependencies\":["
                    + "{\"group\":\"g\",\"version\":\"1.0\"},"
                    + "{\"group\":\"g\",\"name\":\"ok\",\"version\":\"2.0\"},"
                    + "{\"group\":\"g\",\"name\":\"noversion\"}"
                    + "]}";
            ParseOutcome<Dependency> outcome = new JsonManifestParser().parse(json, "m.json");
            assertFalse(outcome.fatal());
            assertEquals(2, outcome.issues().size());
            assertTrue(outcome.issues().stream().allMatch(i -> IssueKinds.ENTRY_FIELD_ERROR.equals(i.kind())));
            assertEquals(1, outcome.items().size());
            assertEquals("ok", outcome.items().get(0).name());
        }

        @Test
        @DisplayName("版本号无法识别 -> ENTRY_FIELD_ERROR")
        void invalidVersion() {
            ParseOutcome<Dependency> outcome = new JsonManifestParser()
                    .parse("{\"dependencies\":[{\"name\":\"x\",\"version\":\"@@@\"}]}", "m.json");
            assertEquals(IssueKinds.ENTRY_FIELD_ERROR, outcome.issues().get(0).kind());
            assertTrue(outcome.items().isEmpty());
        }
    }

    @Nested
    @DisplayName("pom.xml 清单")
    class PomManifestCases {

        @Test
        @DisplayName("XML 损坏 -> FILE_FORMAT_ERROR")
        void brokenXml() {
            ParseOutcome<Dependency> outcome = new PomManifestParser()
                    .parse("<project><dependencies>", "pom.xml");
            assertTrue(outcome.fatal());
            assertEquals(IssueKinds.FILE_FORMAT_ERROR, outcome.issues().get(0).kind());
        }

        @Test
        @DisplayName("缺 version 与无法解析的属性 -> ENTRY_FIELD_ERROR")
        void unresolvedProperty() {
            String pom = """
                    <project>
                      <modelVersion>4.0.0</modelVersion>
                      <dependencies>
                        <dependency>
                          <groupId>a</groupId><artifactId>b</artifactId>
                          <version>${unknown.version}</version>
                        </dependency>
                        <dependency>
                          <groupId>c</groupId><artifactId>d</artifactId>
                        </dependency>
                      </dependencies>
                    </project>
                    """;
            ParseOutcome<Dependency> outcome = new PomManifestParser().parse(pom, "pom.xml");
            assertEquals(2, outcome.issues().size());
            assertTrue(outcome.issues().stream().allMatch(i -> IssueKinds.ENTRY_FIELD_ERROR.equals(i.kind())));
        }

        @Test
        @DisplayName("${project.version} 可正确解析")
        void projectVersionResolves() {
            String pom = """
                    <project>
                      <modelVersion>4.0.0</modelVersion>
                      <version>3.3.3</version>
                      <dependencies>
                        <dependency>
                          <groupId>a</groupId><artifactId>b</artifactId>
                          <version>${project.version}</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """;
            ParseOutcome<Dependency> outcome = new PomManifestParser().parse(pom, "pom.xml");
            assertTrue(outcome.issues().isEmpty());
            assertEquals("3.3.3", outcome.items().get(0).version());
        }
    }

    @Nested
    @DisplayName("文本清单")
    class TextManifestCases {

        @Test
        @DisplayName("行数段数错误逐行拒绝并带行号，好行保留")
        void badLineRejected() {
            String text = "maven,g:a:1.0\nthis-is-not-valid\nnpm,lodash:4.0";
            ParseOutcome<Dependency> outcome = new TextManifestParser().parse(text, "deps.txt");
            assertEquals(1, outcome.issues().size());
            assertEquals(IssueKinds.ENTRY_FIELD_ERROR, outcome.issues().get(0).kind());
            assertEquals(2, outcome.items().size());
            assertTrue(outcome.issues().get(0).source().contains(":2"));
        }
    }

    @Nested
    @DisplayName("漏洞库三种格式")
    class LibraryCases {

        @Test
        @DisplayName("JSON 库损坏 -> FILE_FORMAT_ERROR")
        void brokenJsonLibrary() {
            ParseOutcome<VulnerabilityRule> outcome = new JsonVulnerabilityLibraryParser()
                    .parse("{vulnerabilities:", "db.json");
            assertTrue(outcome.fatal());
            assertEquals(IssueKinds.FILE_FORMAT_ERROR, outcome.issues().get(0).kind());
        }

        @Test
        @DisplayName("YAML 库损坏 -> FILE_FORMAT_ERROR")
        void brokenYamlLibrary() {
            ParseOutcome<VulnerabilityRule> outcome = new YamlVulnerabilityLibraryParser()
                    .parse("vulnerabilities:\n - id: x\n   id: y\n bad: : :", "db.yaml");
            assertTrue(outcome.fatal());
            assertEquals(IssueKinds.FILE_FORMAT_ERROR, outcome.issues().get(0).kind());
        }

        @Test
        @DisplayName("区间写错 -> VERSION_RANGE_ERROR，与字段缺失区分")
        void badRangeClassified() {
            String json = "{\"vulnerabilities\":["
                    + "{\"id\":\"CVE-1\",\"package\":\"g:a\",\"affectedVersions\":\"[2.0,1.0)\",\"severity\":\"high\"},"
                    + "{\"id\":\"CVE-2\",\"affectedVersions\":\"[1.0,2.0)\",\"severity\":\"high\"}"
                    + "]}";
            ParseOutcome<VulnerabilityRule> outcome = new JsonVulnerabilityLibraryParser().parse(json, "db.json");
            assertEquals(2, outcome.issues().size());
            assertEquals(IssueKinds.VERSION_RANGE_ERROR, outcome.issues().get(0).kind());
            assertEquals(IssueKinds.ENTRY_FIELD_ERROR, outcome.issues().get(1).kind());
            assertTrue(outcome.items().isEmpty());
        }

        @Test
        @DisplayName("文本库段数不足 -> ENTRY_FIELD_ERROR")
        void textLibraryBadLine() {
            ParseOutcome<VulnerabilityRule> outcome = new TextVulnerabilityLibraryParser()
                    .parse("CVE-1|g:a", "db.txt");
            assertEquals(IssueKinds.ENTRY_FIELD_ERROR, outcome.issues().get(0).kind());
        }

        @Test
        @DisplayName("非法 severity / priority 被拒绝")
        void invalidSeverity() {
            String json = "{\"vulnerabilities\":["
                    + "{\"id\":\"CVE-1\",\"package\":\"g:a\",\"affectedVersions\":\"[1.0,2.0)\",\"severity\":\"weird\"},"
                    + "{\"id\":\"CVE-2\",\"package\":\"g:b\",\"affectedVersions\":\"[1.0,2.0)\",\"priority\":\"P9\"}"
                    + "]}";
            ParseOutcome<VulnerabilityRule> outcome = new JsonVulnerabilityLibraryParser().parse(json, "db.json");
            assertEquals(2, outcome.issues().size());
            assertTrue(outcome.issues().stream().allMatch(i -> IssueKinds.ENTRY_FIELD_ERROR.equals(i.kind())));
        }
    }
}
