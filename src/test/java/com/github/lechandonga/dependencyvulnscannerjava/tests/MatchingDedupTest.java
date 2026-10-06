package com.github.lechandonga.dependencyvulnscannerjava.tests;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.model.Priority;
import com.github.lechandonga.dependencyvulnscannerjava.model.Severity;
import com.github.lechandonga.dependencyvulnscannerjava.model.VulnerabilityRule;
import com.github.lechandonga.dependencyvulnscannerjava.service.LibrarySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanEngine;
import com.github.lechandonga.dependencyvulnscannerjava.version.VersionRange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：漏洞匹配、重叠区间去重与结论确定性。 */
@DisplayName("业务：匹配与去重")
class MatchingDedupTest {

    private final ScanEngine engine = new ScanEngine();

    private VulnerabilityRule rule(String id, String pkg, String range, Severity severity, Priority priority) {
        return new VulnerabilityRule(id, "maven",
                pkg.contains(":") ? pkg.substring(0, pkg.indexOf(':')) : null,
                pkg.contains(":") ? pkg.substring(pkg.indexOf(':') + 1) : pkg,
                range, VersionRange.parse(range), severity, priority, "t-" + id, "upgrade", "db.json");
    }

    private Dependency dep(String pkg, String version) {
        int colon = pkg.indexOf(':');
        return new Dependency("maven", pkg.substring(0, colon), pkg.substring(colon + 1), version, "m.json");
    }

    @Test
    @DisplayName("同一漏洞多个重叠区间同时命中时只产生一条结论")
    void overlappingRangesDeduplicated() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-A", "g:a", "[1.0,2.0)", Severity.HIGH, Priority.P1),
                rule("CVE-A", "g:a", "[1.5,3.0)", Severity.HIGH, Priority.P1));
        LibrarySnapshot snapshot = new LibrarySnapshot("fp", 0, rules);
        List<Finding> findings = engine.scan(List.of(dep("g:a", "1.8")), snapshot);
        assertEquals(1, findings.size());
        assertEquals("CVE-A", findings.get(0).vulnerabilityId());
    }

    @Test
    @DisplayName("并集区间的两段都可命中同一漏洞，仍只有一条结论")
    void unionRangeSingleFinding() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-B", "g:b", "[1.0,1.2),[2.0,2.2)", Severity.MEDIUM, null));
        LibrarySnapshot snapshot = new LibrarySnapshot("fp", 0, rules);
        assertEquals(1, engine.scan(List.of(dep("g:b", "1.1")), snapshot).size());
        assertEquals(1, engine.scan(List.of(dep("g:b", "2.1")), snapshot).size());
        assertTrue(engine.scan(List.of(dep("g:b", "1.5")), snapshot).isEmpty());
    }

    @Test
    @DisplayName("不同漏洞编号重叠时各自出结论，按优先级+编号确定排序")
    void distinctVulnerabilitiesBothReported() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-LOW", "g:a", "[1.0,2.0)", Severity.LOW, Priority.P3),
                rule("CVE-CRIT", "g:a", "[1.0,2.0)", Severity.CRITICAL, Priority.P0));
        LibrarySnapshot snapshot = new LibrarySnapshot("fp", 0, rules);
        List<Finding> findings = engine.scan(List.of(dep("g:a", "1.5")), snapshot);
        assertEquals(2, findings.size());
        assertEquals("CVE-CRIT", findings.get(0).vulnerabilityId());
        assertEquals(Priority.P0, findings.get(0).priority());
    }

    @Test
    @DisplayName("重复依赖条目归一化后只评估一次")
    void duplicateDependenciesNormalized() {
        List<Dependency> deps = List.of(dep("g:a", "1.5"), dep("g:a", "1.5"));
        List<Dependency> normalized = engine.normalizeDependencies(deps);
        assertEquals(1, normalized.size());
        LibrarySnapshot snapshot =
                new LibrarySnapshot("fp", 0, List.of(rule("CVE-A", "g:a", "[1.0,2.0)", Severity.HIGH, null)));
        assertEquals(1, engine.scan(normalized, snapshot).size());
    }

    @Test
    @DisplayName("不同生态或坐标不串匹配")
    void ecosystemAndCoordinateIsolation() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-X", "g:a", "[1.0,2.0)", Severity.HIGH, null));
        LibrarySnapshot snapshot = new LibrarySnapshot("fp", 0, rules);
        assertTrue(engine.scan(List.of(new Dependency("npm", null, "a", "1.5", "p")), snapshot).isEmpty());
        assertTrue(engine.scan(List.of(dep("g:other", "1.5")), snapshot).isEmpty());
        assertEquals(1, engine.scan(List.of(dep("g:a", "1.5")), snapshot).size());
    }

    @Test
    @DisplayName("相同输入重复扫描输出完全一致（可复现）")
    void deterministicOutput() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-B", "g:a", "[1.0,3.0)", Severity.HIGH, null),
                rule("CVE-A", "g:a", "[1.0,2.0)", Severity.CRITICAL, null),
                rule("CVE-A", "g:a", "[2.0,4.0]", Severity.CRITICAL, null));
        LibrarySnapshot snapshot = new LibrarySnapshot("fingerprint-xyz", 0, rules);
        List<Dependency> deps = List.of(dep("g:a", "2.0"), dep("g:a", "1.0"));
        List<Finding> first = engine.scan(deps, snapshot);
        List<Finding> second = engine.scan(deps, snapshot);
        assertEquals(first, second);
        // CVE-B 覆盖两个版本各一条；CVE-A 两段区间对同一依赖同编号只出一条，共 4 条
        assertEquals(4, first.size());
        assertEquals(4, first.stream().map(f -> f.vulnerabilityId() + "@" + f.dependencyVersion()).distinct().count());
    }

    @Test
    @DisplayName("未显式给优先级时按严重程度推导")
    void priorityDerivedFromSeverity() {
        List<VulnerabilityRule> rules = List.of(
                rule("CVE-S", "g:a", "[1.0,2.0)", Severity.HIGH, null));
        LibrarySnapshot snapshot = new LibrarySnapshot("fp", 0, rules);
        assertEquals(Priority.P1, engine.scan(List.of(dep("g:a", "1.5")), snapshot).get(0).priority());
    }
}
