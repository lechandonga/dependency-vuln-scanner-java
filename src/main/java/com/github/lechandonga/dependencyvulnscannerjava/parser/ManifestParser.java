package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;

import java.util.Locale;

/** 依赖清单解析器：支持 JSON / Maven pom.xml / 文本锁文件。 */
public interface ManifestParser {

    /** 按文件名或显式 hint 判定是否支持。 */
    boolean supports(String filename, String formatHint);

    ParseOutcome<Dependency> parse(String content, String sourceName);

    static String formatOf(String filename, String formatHint) {
        if (formatHint != null && !formatHint.isBlank()) {
            return formatHint.trim().toLowerCase(Locale.ROOT);
        }
        String lower = filename == null ? "" : filename.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".json")) {
            return "json";
        }
        if (lower.endsWith(".xml") || lower.equals("pom.xml") || lower.contains("pom")) {
            return "pom";
        }
        if (lower.endsWith(".txt") || lower.endsWith(".lock")) {
            return "text";
        }
        throw new IllegalArgumentException("无法根据文件名推断清单格式，请显式指定 format: " + filename);
    }
}
