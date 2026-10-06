package com.github.lechandonga.dependencyvulnscannerjava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * Maven 风格版本区间：
 * <ul>
 *   <li>{@code [1.0,2.0)} 闭开区间；{@code [1.0,2.0]} 闭区间</li>
 *   <li>{@code [1.5]} 精确版本；{@code (,1.0)} / {@code [2.0,)} 单侧区间</li>
 *   <li>逗号分隔的并集；{@code *} 表示全部版本</li>
 * </ul>
 */
public final class VersionRange {

    private final String raw;
    private final List<Interval> intervals;

    private VersionRange(String raw, List<Interval> intervals) {
        this.raw = raw;
        this.intervals = List.copyOf(intervals);
    }

    public static VersionRange parse(String text) {
        if (text == null) {
            throw new RangeSyntaxException("版本区间为空");
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            throw new RangeSyntaxException("版本区间为空");
        }
        if ("*".equals(trimmed) || "all".equalsIgnoreCase(trimmed)) {
            return new VersionRange(trimmed, List.of(new Interval(null, false, null, false, null)));
        }
        List<Interval> list = new ArrayList<>();
        int pos = 0;
        boolean found = false;
        while (pos < trimmed.length()) {
            while (pos < trimmed.length() && Character.isWhitespace(trimmed.charAt(pos))) {
                pos++;
            }
            if (pos >= trimmed.length()) {
                break;
            }
 char open = trimmed.charAt(pos);
            if (open != '[' && open != '(') {
                throw new RangeSyntaxException("区间必须以 [ 或 ( 开始: " + trimmed);
            }
            int close = -1;
            for (int p = pos + 1; p < trimmed.length(); p++) {
                char c = trimmed.charAt(p);
                if (c == ']' || c == ')') {
                    close = p;
                    break;
                }
                if (c == '[' || c == '(') {
                    throw new RangeSyntaxException("区间内出现未闭合的嵌套括号: " + trimmed);
                }
            }
            if (close < 0) {
                throw new RangeSyntaxException("区间缺少闭合括号: " + trimmed);
            }
            char closeCh = trimmed.charAt(close);
            String body = trimmed.substring(pos + 1, close);
            list.add(parseInterval(open == '[', closeCh == ']', body, trimmed));
            found = true;
            pos = close + 1;
            while (pos < trimmed.length() && Character.isWhitespace(trimmed.charAt(pos))) {
                pos++;
            }
            if (pos < trimmed.length() && trimmed.charAt(pos) != ',') {
                throw new RangeSyntaxException("多个区间之间必须用逗号分隔: " + trimmed);
            }
            if (pos < trimmed.length()) {
                pos++;
            }
        }
        if (!found) {
            throw new RangeSyntaxException("无法解析的版本区间: " + trimmed);
        }
        return new VersionRange(trimmed, list);
    }

    private static Interval parseInterval(boolean lowerInclusive, boolean upperInclusive,
                                          String body, String full) {
        int comma = body.indexOf(',');
        if (comma < 0) {
            // 精确版本 [1.5]
            String v = body.trim();
            if (v.isEmpty()) {
                throw new RangeSyntaxException("精确版本不能为空: " + full);
            }
            if (!lowerInclusive || !upperInclusive) {
                throw new RangeSyntaxException("精确版本必须使用闭区间 [x]: " + full);
            }
            Version exact = safeVersion(v, full);
            return new Interval(exact, true, exact, true, exact);
        }
        String lower = body.substring(0, comma).trim();
        String upper = body.substring(comma + 1).trim();
        if (lower.isEmpty() && upper.isEmpty()) {
            throw new RangeSyntaxException("区间上下界不能同时为空: " + full);
        }
        Version low = lower.isEmpty() ? null : safeVersion(lower, full);
        Version high = upper.isEmpty() ? null : safeVersion(upper, full);
        if (low != null && high != null && low.compareTo(high) > 0) {
            throw new RangeSyntaxException("区间下界大于上界: " + full);
        }
        return new Interval(low, lowerInclusive, high, upperInclusive, null);
    }

    private static Version safeVersion(String v, String full) {
        try {
            return Version.parse(v);
        } catch (IllegalArgumentException e) {
            throw new RangeSyntaxException("区间边界版本非法(" + e.getMessage() + "): " + full);
        }
    }

    public boolean contains(String versionText) {
        Version v = Version.parse(versionText);
        for (Interval interval : intervals) {
            if (interval.contains(v)) {
                return true;
            }
        }
        return false;
    }

    public String raw() {
        return raw;
    }

    @Override
    public String toString() {
        return raw;
    }

    private record Interval(Version lower, boolean lowerInclusive, Version upper, boolean upperInclusive,
                            Version exactVersion) {
        boolean contains(Version v) {
            if (exactVersion != null) {
                return exactVersion.toString().equals(v.toString());
            }
            if (lower != null) {
                int cmp = v.compareTo(lower);
                if (cmp < 0 || (cmp == 0 && !lowerInclusive)) {
                    return false;
                }
            }
            if (upper != null) {
                int cmp = v.compareTo(upper);
                if (cmp > 0 || (cmp == 0 && !upperInclusive)) {
                    return false;
                }
            }
            return true;
        }
    }
}
