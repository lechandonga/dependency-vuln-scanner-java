package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.VulnerabilityRule;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.Version;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.VersionRange;
import com.github.lechandonga.dependencyvulnscannerjava.db.VulnerabilitySnapshot;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 无状态扫描引擎。对同一份依赖清单与同一快照，输出字节级可复现：
 * <ul>
 *   <li>规则按快照稳定顺序遍历；</li>
 *   <li>去重键为 (漏洞编号, 依赖坐标, 依赖版本)，重叠区间只出一条结论，
 *       保留区间表达式最小（字典序）的命中解释；</li>
 *   <li>结果按 优先级 → 严重度 → CVSS → 漏洞编号 → 依赖坐标 稳定排序。</li>
 * </ul>
 */
@Component
public class ScannerEngine {

    public ScanReport scan(List<Dependency> dependencies, VulnerabilitySnapshot snapshot) {
        List<VulnerabilityRule> rules = snapshot.sortedRules();
        Map<String, Finding> dedup = new LinkedHashMap<>();

        for (VulnerabilityRule rule : rules) {
            for (Dependency dependency : dependencies) {
                if (!rule.type().equalsIgnoreCase(dependency.type())
                        || !rule.name().equalsIgnoreCase(dependency.name())
                        || !rule.matchesGroup(dependency.group())) {
                    continue;
                }
                Version version = Version.parse(dependency.version());
                // 多区间命中（重叠区间）只解释一次：以漏洞库中声明的第一个命中区间为准，
                // 结论确定且与条目书写顺序对应
                String matchedExpression = null;
                for (VersionRange range : rule.affectedRanges()) {
                    if (range.contains(version)) {
                        matchedExpression = range.describe();
                        break;
                    }
                }
                if (matchedExpression == null) {
                    continue;
                }
                String key = rule.vulnId() + "|" + dependency.coordinate().toLowerCase(Locale.ROOT)
                        + "|" + dependency.version();
                Finding finding = new Finding(
                        rule.vulnId(),
                        dependency.coordinate(),
                        dependency.version(),
                        dependency.type(),
                        matchedExpression,
                        rule.severity(),
                        PriorityResolver.resolve(rule),
                        rule.cvss(),
                        String.join(" | ", rule.fixedVersions()),
                        rule.description());
                dedup.putIfAbsent(key, finding);
            }
        }

        List<Finding> findings = new ArrayList<>(dedup.values());
        findings.sort(Comparator
                .comparingInt((Finding f) -> Integer.parseInt(f.priority().substring(1)))
                .thenComparing(f -> f.severity() == null ? "ZZZ" : f.severity(),
                        Comparator.reverseOrder())
                .thenComparing(f -> f.cvss() == null ? -1 : f.cvss(), Comparator.reverseOrder())
                .thenComparing(Finding::vulnId)
                .thenComparing(Finding::dependencyCoordinate));
        return new ScanReport(snapshot.contentHash(), dependencies.size(),
                findings.size(), dependencies, findings);
    }
}
