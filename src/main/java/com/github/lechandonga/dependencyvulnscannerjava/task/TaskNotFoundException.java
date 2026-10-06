package com.github.lechandonga.dependencyvulnscannerjava.task;

public class TaskNotFoundException extends RuntimeException {
    public TaskNotFoundException(String taskId) {
        super("扫描任务不存在: " + taskId);
    }
}
