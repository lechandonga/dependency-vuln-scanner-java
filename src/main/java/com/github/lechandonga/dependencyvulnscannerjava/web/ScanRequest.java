package com.github.lechandonga.dependencyvulnscannerjava.web;

/**
 * 扫描提交请求。content 为清单原文（本地字符串，不接受任何 URL）；
 * format 支持 json/xml/csv，manifestName 仅用于错误定位与展示。
 */
public record ScanRequest(String content, String format, String manifestName) {
}
