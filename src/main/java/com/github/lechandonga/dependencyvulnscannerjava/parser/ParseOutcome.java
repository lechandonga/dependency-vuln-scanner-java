package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.List;

/**
 * 解析结果：任何问题都显式收集，绝不静默跳过。
 *
 * @param fatal true 表示文件整体无法解析，items 必为空
 */
public record ParseOutcome<T>(List<T> items, List<Issue> issues, boolean fatal) {

    public static <T> ParseOutcome<T> fatal(Issue issue) {
        return new ParseOutcome<>(List.of(), List.of(issue), true);
    }

    public boolean hasIssues() {
        return !issues.isEmpty();
    }
}
