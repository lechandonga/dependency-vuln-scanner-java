package com.github.lechandonga.dependencyvulnscannerjava.web.dto;

/** 扫描提交请求：content 直传或 filename 读取本地清单目录，二选一。 */
public record ScanRequest(String filename, String content, String format) {
}
