package com.github.lechandonga.dependencyvulnscannerjava.model;

/** 一条扫描结论：某个依赖命中了某条漏洞规则。 */
public record Finding(String vulnerabilityId,
                      String title,
                      String ecosystem,
                      String coordinate,
                      String dependencyVersion,
                      String matchedRange,
                      Severity severity,
                      Priority priority,
                      String recommendation) {
}
