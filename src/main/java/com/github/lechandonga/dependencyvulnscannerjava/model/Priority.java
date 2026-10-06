package com.github.lechandonga.dependencyvulnscannerjava.model;

/** 建议处理优先级，P0 最高。 */
public enum Priority {
    P0, P1, P2, P3;

    public static Priority fromRaw(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String normalized = raw.trim().toUpperCase();
        return switch (normalized) {
            case "P0", "P1", "P2", "P3" -> Priority.valueOf(normalized);
            default -> null;
        };
    }
}
