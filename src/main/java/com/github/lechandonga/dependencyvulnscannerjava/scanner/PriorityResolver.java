package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.VulnerabilityRule;

/**
 * 处理优先级推导：漏洞库显式 priority 优先；否则按 severity 推导；
 * severity 缺失时按 CVSS 分值分档；都没有时给最低优先级 P4。
 * <pre>
 * CRITICAL → P1（立即修复）   HIGH → P2（尽快修复）
 * MEDIUM   → P3（计划修复）   LOW/未知 → P4（择机处理）
 * </pre>
 */
final class PriorityResolver {

    private PriorityResolver() {
    }

    static String resolve(VulnerabilityRule rule) {
        if (rule.priority() != null) {
            return rule.priority();
        }
        if (rule.severity() != null) {
            return switch (rule.severity()) {
                case "CRITICAL" -> "P1";
                case "HIGH" -> "P2";
                case "MEDIUM" -> "P3";
                default -> "P4";
            };
        }
        if (rule.cvss() != null) {
            double score = rule.cvss();
            if (score >= 9.0) {
                return "P1";
            }
            if (score >= 7.0) {
                return "P2";
            }
            if (score >= 4.0) {
                return "P3";
            }
        }
        return "P4";
    }
}
