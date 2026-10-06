package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.Finding;

import java.util.List;

/**
 * 扫描的完整产物：输入清单副本、漏洞库快照指纹与最终结论。
 * 只有扫描成功完成时才会生成该对象，避免半成品结果可见。
 */
public record ScanReport(
        String vulnerabilityDbHash,
        int dependencyCount,
        int findingCount,
        List<Dependency> dependencies,
        List<Finding> findings) {

    public ScanReport {
        dependencies = List.copyOf(dependencies);
        findings = List.copyOf(findings);
    }
}
