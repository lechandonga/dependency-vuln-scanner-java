package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.List;

/**
 * 扫描任务的不可变视图（状态更新通过 {@link ScanTaskService} 原子替换）。
 */
public record ScanTask(String id,
                       TaskStatus status,
                       String stage,
                       String manifestFingerprint,
                       String libraryFingerprint,
                       int dependencyCount,
                       List<Finding> findings,
                       FailureType failureType,
                       String failureMessage,
                       List<Issue> issues,
                       long createdAt,
                       long updatedAt) {

}
