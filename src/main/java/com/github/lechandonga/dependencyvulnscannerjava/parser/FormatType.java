package com.github.lechandonga.dependencyvulnscannerjava.parser;

import java.util.Locale;

public enum FormatType {
    JSON,
    XML,
    CSV;

    public static FormatType fromName(String name) {
        String lower = name.trim().toLowerCase(Locale.ROOT);
        return switch (lower) {
            case "json" -> JSON;
            case "xml", "pom" -> XML;
            case "csv" -> CSV;
            default -> throw new IllegalArgumentException("不支持的格式: " + name + "（仅支持 json/xml/csv）");
        };
    }
}
