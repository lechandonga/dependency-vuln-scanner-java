package com.github.lechandonga.dependencyvulnscannerjava.service;

/** 任务失败原因分类。 */
public enum FailureType {
    /** 清单问题：格式错误、字段缺失、版本无法识别等（调用方需修改清单）。 */
    MANIFEST_ERROR,
    /** 漏洞库问题：库文件损坏、区间写错、规则重复等（管理员需修复库）。 */
    LIBRARY_ERROR,
    /** 服务自身问题：IO 异常、内部状态异常等（可重试）。 */
    SERVICE_ERROR
}
