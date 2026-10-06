package com.github.lechandonga.dependencyvulnscannerjava.core.model;

/**
 * 一次命中结论。去重键为 {@code (vulnId, dependencyCoordinate, dependencyVersion)}：
 * 同一漏洞的多个重叠区间命中同一依赖只产生一条 Finding。
 */
public record Finding(
        String vulnId,
        String dependencyCoordinate,
        String dependencyVersion,
        String packageType,
        String matchedRangeExpression,
        String severity,
        String priority,
        Double cvss,
        String fixedVersions,
        String description) {
}
