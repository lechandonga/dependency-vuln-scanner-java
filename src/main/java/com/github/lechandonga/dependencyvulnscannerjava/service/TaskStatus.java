package com.github.lechandonga.dependencyvulnscannerjava.service;

/** 任务状态：PENDING -> RUNNING -> SUCCEEDED / FAILED，失败后不再变化。 */
public enum TaskStatus {
    PENDING,
    RUNNING,
    SUCCEEDED,
    FAILED
}
