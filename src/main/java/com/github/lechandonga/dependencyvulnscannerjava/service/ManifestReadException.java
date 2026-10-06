package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.List;

/** 清单读取/解析失败。 */
public class ManifestReadException extends RuntimeException {

    private final transient List<Issue> issues;

    public ManifestReadException(String message, List<Issue> issues) {
        super(message);
        this.issues = List.copyOf(issues);
    }

    public List<Issue> issues() {
        return issues;
    }
}
