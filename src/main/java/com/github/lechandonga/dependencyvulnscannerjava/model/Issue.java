package com.github.lechandonga.dependencyvulnscannerjava.model;

/**
 * 解析问题。
 *
 * @param kind     问题类别（见各解析器常量）
 * @param source   来源文件名或条目位置
 * @param index    条目序号（从 0 开始），无法定位时为 -1
 * @param message  人类可读描述
 */
public record Issue(String kind, String source, int index, String message) {

    @Override
    public String toString() {
        String loc = source == null ? "" : source;
        if (index >= 0) {
            loc = loc + "#" + index;
        }
        return "[" + kind + "] " + loc + (loc.isEmpty() ? "" : ": ") + message;
    }
}
