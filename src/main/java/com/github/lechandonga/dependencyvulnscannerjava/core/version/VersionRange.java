package com.github.lechandonga.dependencyvulnscannerjava.core.version;

import java.util.ArrayList;
import java.util.List;

/**
 * 漏洞影响版本区间，支持两种语法（均可在漏洞库中使用，解析规则确定）：
 * <ol>
 *   <li>Maven 版本区间语法（推荐）：
 *     <ul>
 *       <li>{@code [1.0,2.0)}：半开区间，含 1.0、不含 2.0；</li>
 *       <li>{@code [1.0,2.0]}：闭区间；{@code (1.0,2.0)}：开区间；</li>
 *       <li>{@code [1.0,)}：下界及以上；{@code (,2.0)}：上界以下；</li>
 *       <li>{@code [1.5]}：精确版本（推荐/固定版本请写在 fixedVersions 字段）。</li>
 *     </ul>
 *   </li>
 *   <li>简化比较表达式：{@code >=1.0}, {@code >1.0}, {@code <=2.0}, {@code <2.0},
 *       {@code =1.0}（或直接写 {@code 1.0}），多个条件用逗号/分号连接表示交集，
 *       例如 {@code >=1.0,<2.0}。</li>
 * </ol>
 * 区间非法（空串、括号不匹配、下界大于上界等）会抛 {@link RangeParseException}，
 * 由调用方归入“条目级错误”，绝不静默忽略。
 */
public final class VersionRange {

    private final String raw;
    private final Version lower;
    private final boolean lowerInclusive;
    private final Version upper;
    private final boolean upperInclusive;
    private final String canonicalKey;

    private VersionRange(String raw, Version lower, boolean lowerInclusive,
                         Version upper, boolean upperInclusive) {
        this.raw = raw;
        this.lower = lower;
        this.lowerInclusive = lowerInclusive;
        this.upper = upper;
        this.upperInclusive = upperInclusive;
        this.canonicalKey = (lowerInclusive ? "[" : "(")
                + (lower == null ? "" : lower.canonical())
                + ","
                + (upper == null ? "" : upper.canonical())
                + (upperInclusive ? "]" : ")");
    }

    public static VersionRange parse(String text) {
        if (text == null) {
            throw new RangeParseException("版本区间不能为 null");
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            throw new RangeParseException("版本区间不能为空");
        }
        try {
            if (trimmed.startsWith("[") || trimmed.startsWith("(")) {
                return parseMaven(trimmed);
            }
            return parseSimple(trimmed);
        } catch (RangeParseException e) {
            throw e;
        } catch (VersionParseException e) {
            throw new RangeParseException("版本区间 '" + text + "' 中存在无法解析的版本号: " + e.getMessage());
        }
    }

    private static VersionRange parseMaven(String text) {
        char open = text.charAt(0);
        if (!text.endsWith("]") && !text.endsWith(")")) {
            throw new RangeParseException("版本区间 '" + text + "' 缺少结束括号 ']' 或 ')'");
        }
        char close = text.charAt(text.length() - 1);
        String body = text.substring(1, text.length() - 1);
        if (body.isBlank()) {
            throw new RangeParseException("版本区间 '" + text + "' 括号内为空");
        }

        boolean lowerInclusive = open == '[';
        boolean upperInclusive = close == ']';

        if (!body.contains(",")) {
            if (!lowerInclusive || !upperInclusive) {
                throw new RangeParseException("精确版本必须写为 '[版本]': '" + text + "'");
            }
            Version exact = Version.parse(body.trim());
            return new VersionRange(text, exact, true, exact, true);
        }

        int comma = body.indexOf(',');
        if (body.indexOf(',', comma + 1) >= 0) {
            throw new RangeParseException("版本区间 '" + text + "' 只能包含一个逗号");
        }
        String lowerText = body.substring(0, comma).trim();
        String upperText = body.substring(comma + 1).trim();
        if (lowerText.isEmpty() && upperText.isEmpty()) {
            throw new RangeParseException("版本区间 '" + text + "' 的上下界不能同时为空");
        }
        Version lower = lowerText.isEmpty() ? null : Version.parse(lowerText);
        Version upper = upperText.isEmpty() ? null : Version.parse(upperText);
        return validateAndBuild(text, lower, lowerInclusive, upper, upperInclusive);
    }

    private static VersionRange parseSimple(String text) {
        List<Part> parts = new ArrayList<>();
        String[] clauses = text.split("[,;]");
        for (String clause : clauses) {
            String c = clause.trim();
            if (c.isEmpty()) {
                throw new RangeParseException("版本区间 '" + text + "' 中存在空条件");
            }
            String op;
            String versionText;
            if (c.startsWith(">=") || c.startsWith("<=") || c.startsWith("==")) {
                op = c.substring(0, 2);
                versionText = c.substring(2).trim();
            } else if (c.charAt(0) == '>' || c.charAt(0) == '<' || c.charAt(0) == '=') {
                op = c.substring(0, 1);
                versionText = c.substring(1).trim();
            } else {
                op = "=";
                versionText = c;
            }
            if (versionText.isEmpty()) {
                throw new RangeParseException("版本区间 '" + text + "' 中条件 '" + c + "' 缺少版本号");
            }
            parts.add(new Part(op, Version.parse(versionText)));
        }

        Version lower = null;
        boolean lowerInclusive = false;
        Version upper = null;
        boolean upperInclusive = false;
        Version exact = null;
        for (Part part : parts) {
            switch (part.op()) {
                case ">=" -> {
                    if (lower == null || part.version().compareTo(lower) > 0) {
                        lower = part.version();
                        lowerInclusive = true;
                    }
                }
                case ">" -> {
                    if (lower == null || part.version().compareTo(lower) >= 0) {
                        lower = part.version();
                        lowerInclusive = false;
                    }
                }
                case "<=" -> {
                    if (upper == null || part.version().compareTo(upper) < 0) {
                        upper = part.version();
                        upperInclusive = true;
                    }
                }
                case "<" -> {
                    if (upper == null || part.version().compareTo(upper) <= 0) {
                        upper = part.version();
                        upperInclusive = false;
                    }
                }
                case "=", "==" -> {
                    if (exact != null && exact.compareTo(part.version()) != 0) {
                        throw new RangeParseException("版本区间 '" + text + "' 声明了多个不同的精确版本");
                    }
                    exact = part.version();
                }
                default -> throw new RangeParseException("不支持的比较运算符: " + part.op());
            }
        }
        if (exact != null) {
            return new VersionRange(text, exact, true, exact, true);
        }
        return validateAndBuild(text, lower, lowerInclusive, upper, upperInclusive);
    }

    private static VersionRange validateAndBuild(String raw, Version lower, boolean lowerInclusive,
                                                 Version upper, boolean upperInclusive) {
        if (lower == null && upper == null) {
            throw new RangeParseException("版本区间 '" + raw + "' 至少需要一个边界");
        }
        if (lower != null && upper != null) {
            int cmp = lower.compareTo(upper);
            if (cmp > 0) {
                throw new RangeParseException(
                        "版本区间 '" + raw + "' 的下界 " + lower + " 大于上界 " + upper);
            }
            if (cmp == 0 && !(lowerInclusive && upperInclusive)) {
                throw new RangeParseException(
                        "版本区间 '" + raw + "' 的上下界同为 " + lower + " 但边界不都包含，区间为空");
            }
        }
        return new VersionRange(raw, lower, lowerInclusive, upper, upperInclusive);
    }

    public boolean contains(Version version) {
        if (lower != null) {
            int cmp = version.compareTo(lower);
            if (cmp < 0 || (cmp == 0 && !lowerInclusive)) {
                return false;
            }
        }
        if (upper != null) {
            int cmp = version.compareTo(upper);
            if (cmp > 0 || (cmp == 0 && !upperInclusive)) {
                return false;
            }
        }
        return true;
    }

    /** 面向用户的可读边界描述，例如 {@code [1.0,2.0)}，用于命中结论解释。 */
    public String describe() {
        if (lower != null && upper != null && lower.compareTo(upper) == 0) {
            return "[" + lower + "]";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(lower == null ? '(' : (lowerInclusive ? '[' : '('));
        sb.append(lower == null ? "" : lower);
        sb.append(',');
        sb.append(upper == null ? "" : upper);
        sb.append(upper == null ? ')' : (upperInclusive ? ']' : ')'));
        return sb.toString();
    }

    public String raw() {
        return raw;
    }

    /**
     * 规范化区间键：版本号取规范化形式（1.0 与 1 视为相同），
     * 用于识别书写不同但语义相同的重复区间。
     */
    public String canonicalKey() {
        return canonicalKey;
    }

    private record Part(String op, Version version) {
    }
}
