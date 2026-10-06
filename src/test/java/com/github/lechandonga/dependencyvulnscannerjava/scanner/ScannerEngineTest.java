package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.VulnerabilityRule;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.VersionRange;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilitySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.support.BusinessModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessModule("扫描引擎（重叠区间去重、可复现性、优先级排序）")
class ScannerEngineTest {

    private final ScannerEngine engine = new ScannerEngine();

    private VulnerabilityRule rule(String id, String group, String name, String range,
                                  String severity, String priority) {
        return new VulnerabilityRule(id, group, name, "maven",
                List.of(VersionRange.parse(range)), List.of("9.9"),
                severity, null, priority, "desc-" + id, "test");
    }

    private ScanReport run(List<Dependency> deps, List<VulnerabilityRule> rules) {
        VulnerabilitySnapshot snapshot = new VulnerabilitySnapshot(
                "hash1", Instant.now(), List.of("test.json"), rules);
        return engine.scan(deps, snapshot);
    }

    @Test
    @DisplayName("同一漏洞的多个重叠区间命中同一依赖只产生一条结论")
    void overlappingRangesDeduplicated() {
        VulnerabilityRule multi = new VulnerabilityRule(
                "CVE-DUP", "g", "lib", "maven",
                List.of(VersionRange.parse("[1.0,2.0)"),
                        VersionRange.parse("[1.5,2.5)"),
                        VersionRange.parse("(1.2,1.8)")),
                List.of(), "HIGH", null, null, "d", "test");
        Dependency dep = new Dependency("g", "lib", "1.6.0", "maven", "test:1");
        ScanReport report = run(List.of(dep), List.of(multi));
        assertEquals(1, report.findingCount());
        // 命中解释取规范化后字典序最小的区间
        assertEquals("[1.0,2.0)", report.findings().get(0).matchedRangeExpression());
    }

    @Test
    @DisplayName("两条不同漏洞命中同一依赖产生两条结论")
    void distinctVulnsKept() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-A", "g", "lib", "[1.0,2.0)", "HIGH", null),
                rule("CVE-B", "g", "lib", "[1.0,2.0)", "LOW", null));
        Dependency dep = new Dependency("g", "lib", "1.5", "maven", "test:1");
        ScanReport report = run(List.of(dep), rules);
        assertEquals(2, report.findingCount());
    }

    @Test
    @DisplayName("边界版本不误伤：2.0 不命中 [1.0,2.0)，但命中 [1.0,2.0]")
    void boundaryExactness() {
        Dependency dep = new Dependency("g", "lib", "2.0", "maven", "test:1");
        assertEquals(0, run(List.of(dep), List.of(rule("CVE-1", "g", "lib",
                "[1.0,2.0)", "HIGH", null))).findingCount());
        assertEquals(1, run(List.of(dep), List.of(rule("CVE-1", "g", "lib",
                "[1.0,2.0]", "HIGH", null))).findingCount());
    }

    @Test
    @DisplayName("group/name/type 不匹配的规则不产生结论")
    void coordinateMatching() {
        Dependency mavenDep = new Dependency("g", "lib", "1.5", "maven", "t:1");
        Dependency npmDep = new Dependency("", "lib", "1.5", "npm", "t:2");
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-M", "g", "lib", "[1.0,2.0)", "HIGH", null),
                rule("CVE-N", "", "other", "[1.0,2.0)", "HIGH", null));
        ScanReport report = run(List.of(mavenDep, npmDep), rules);
        assertEquals(1, report.findingCount());
        assertEquals("CVE-M", report.findings().get(0).vulnId());
    }

    @Test
    @DisplayName("group 为空的规则匹配任意 group")
    void wildcardGroup() {
        Dependency dep = new Dependency("any.org", "lib", "1.5", "maven", "t:1");
        ScanReport report = run(List.of(dep),
                List.of(rule("CVE-W", "", "lib", "[1.0,2.0)", "HIGH", null)));
        assertEquals(1, report.findingCount());
    }

    @Test
    @DisplayName("同输入重复扫描结论完全一致（确定性可复现）")
    void deterministic() {
        Dependency dep = new Dependency("g", "lib", "1.5", "maven", "t:1");
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-B", "g", "lib", "[1.0,2.0)", "LOW", null),
                rule("CVE-A", "g", "lib", "[1.0,2.0)", "HIGH", null));
        ScanReport first = run(List.of(dep), rules);
        ScanReport second = run(List.of(dep), rules);
        assertEquals(ids(first.findings()), ids(second.findings()));
        assertEquals("CVE-A", first.findings().get(0).vulnId());
    }

    @Test
    @DisplayName("结果按优先级与严重度稳定排序")
    void priorityOrdering() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-P4", "g", "lib", "[1.0,2.0)", "LOW", "P4"),
                rule("CVE-P1", "g", "lib", "[1.0,2.0)", "CRITICAL", "P1"),
                rule("CVE-P2", "g", "lib", "[1.0,2.0)", "HIGH", "P2"));
        Dependency dep = new Dependency("g", "lib", "1.5", "maven", "t:1");
        ScanReport report = run(List.of(dep), rules);
        assertEquals(List.of("CVE-P1", "CVE-P2", "CVE-P4"), ids(report.findings()));
    }

    @Test
    @DisplayName("显式 priority 优先；无 priority 时按 severity 推导")
    void priorityDerivation() {
        Dependency dep = new Dependency("g", "lib", "1.5", "maven", "t:1");
        ScanReport report = run(List.of(dep), List.of(
                rule("CVE-C", "g", "lib", "[1,2)", "CRITICAL", null),
                rule("CVE-H", "g", "lib", "[1,2)", "HIGH", null),
                rule("CVE-M", "g", "lib", "[1,2)", "MEDIUM", null),
                rule("CVE-L", "g", "lib", "[1,2)", "LOW", null)));
        assertEquals(List.of("CVE-C", "CVE-H", "CVE-M", "CVE-L"), ids(report.findings()));
        assertEquals(List.of("P1", "P2", "P3", "P4"),
                report.findings().stream().map(Finding::priority).toList());
        assertFalse(report.findings().isEmpty());
        assertTrue(report.findings().get(0).fixedVersions().contains("9.9"));
    }

    @Test
    @DisplayName("无命中时 findingCount 为 0，依赖计数仍准确")
    void noHit() {
        Dependency dep = new Dependency("g", "lib", "3.0", "maven", "t:1");
        ScanReport report = run(List.of(dep),
                List.of(rule("CVE-1", "g", "lib", "[1.0,2.0)", "HIGH", null)));
        assertEquals(0, report.findingCount());
        assertEquals(1, report.dependencyCount());
    }

    private static List<String> ids(List<Finding> findings) {
        return findings.stream().map(Finding::vulnId).toList();
    }
}
