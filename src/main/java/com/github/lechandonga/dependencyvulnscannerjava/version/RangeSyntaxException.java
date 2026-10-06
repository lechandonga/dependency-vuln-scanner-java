package com.github.lechandonga.dependencyvulnscannerjava.version;

/** 版本区间语法错误，解析器需将其归类为 VERSION_RANGE_ERROR。 */
public class RangeSyntaxException extends IllegalArgumentException {
    public RangeSyntaxException(String message) {
        super(message);
    }
}
