package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import java.util.List;

/**
 * 两份扫描报告的差异。新增/消失以 {@code (漏洞编号, 依赖坐标, 版本)} 为键判定；
 * 键相同但优先级、严重度、区间表达或修复版本发生变化时进入 changed，
 * 每条变化都附带变化原因，解释“哪条结论因为什么变了”。
 */
public record ReportDiff(
        String baseTaskId,
        String targetTaskId,
        String baseDbHash,
        String targetDbHash,
        List<FindingChange> added,
        List<FindingChange> removed,
        List<FindingChange> changed) {

    public record FindingChange(String key, FindingView before, FindingView after, List<String> reasons) {
    }

    public record FindingView(
            String vulnId,
            String dependencyCoordinate,
            String dependencyVersion,
            String matchedRangeExpression,
            String severity,
            String priority,
            Double cvss,
            String fixedVersions) {

        static FindingView of(com.github.lechandonga.dependencyvulnscannerjava.core.model.Finding f) {
            return new FindingView(f.vulnId(), f.dependencyCoordinate(), f.dependencyVersion(),
                    f.matchedRangeExpression(), f.severity(), f.priority(), f.cvss(), f.fixedVersions());
        }
    }
}
