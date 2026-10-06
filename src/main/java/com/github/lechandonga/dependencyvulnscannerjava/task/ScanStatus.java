package com.github.lechandonga.dependencyvulnscannerjava.task;

public enum ScanStatus {
    /** 已提交，等待调度。 */
    QUEUED,
    /** 扫描进行中。 */
    RUNNING,
    /** 成功完成，结果已整体发布。 */
    COMPLETED,
    /** 失败，错误已分类；不存在任何半成品结果。 */
    FAILED
}
