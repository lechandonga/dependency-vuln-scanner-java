package com.github.lechandonga.dependencyvulnscannerjava.parser;

/**
 * 解析失败。{@link #global} 为 true 表示整个文件格式错误，所有条目都不可信；
 * false 表示文件级结构可读、仅单条数据非法（缺字段、版本号/区间写错等）。
 */
public class ParseException extends RuntimeException {

    private final boolean global;
    private final String location;

    public ParseException(boolean global, String location, String message) {
        super(message);
        this.global = global;
        this.location = location;
    }

    public boolean isGlobal() {
        return global;
    }

    public String getLocation() {
        return location;
    }
}
