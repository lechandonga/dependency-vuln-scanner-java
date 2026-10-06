package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.List;

/** 漏洞库加载失败：携带分类后的问题清单。 */
public class LibraryLoadException extends RuntimeException {

    private final transient List<Issue> issues;

    public LibraryLoadException(String message, List<Issue> issues) {
        super(message);
        this.issues = List.copyOf(issues);
    }

    public List<Issue> issues() {
        return issues;
    }
}
