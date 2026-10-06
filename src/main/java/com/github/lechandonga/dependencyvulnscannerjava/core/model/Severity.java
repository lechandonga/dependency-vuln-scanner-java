package com.github.lechandonga.dependencyvulnscannerjava.core.model;

import java.util.Locale;

public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public static Severity from(String text) {
        return Severity.valueOf(text.trim().toUpperCase(Locale.ROOT));
    }
}
