package com.github.lechandonga.dependencyvulnscannerjava.model;

import java.util.Locale;

/** 漏洞严重程度及默认处理优先级映射。 */
public enum Severity {
    CRITICAL(Priority.P0),
    HIGH(Priority.P1),
    MEDIUM(Priority.P2),
    LOW(Priority.P3),
    UNKNOWN(Priority.P2);

    private final Priority defaultPriority;

    Severity(Priority defaultPriority) {
        this.defaultPriority = defaultPriority;
    }

    public Priority defaultPriority() {
        return defaultPriority;
    }

    public static Severity fromRaw(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "critical", "crit", "严重" -> CRITICAL;
            case "high", "高危" -> HIGH;
            case "medium", "moderate", "中危" -> MEDIUM;
            case "low", "低危" -> LOW;
            default -> UNKNOWN;
        };
    }
}
