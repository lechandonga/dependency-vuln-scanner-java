package com.github.lechandonga.dependencyvulnscannerjava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * 通用语义版本：按点/横线/下划线切分数字段与限定词逐段比较。
 * 不依赖任何外部规范库，规则确定且可解释。
 */
public final class Version implements Comparable<Version> {

    private final String raw;
    private final List<Token> tokens;

    private Version(String raw, List<Token> tokens) {
        this.raw = raw;
        this.tokens = List.copyOf(tokens);
    }

    public static Version parse(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("版本号为空");
        }
        String trimmed = text.trim();
        // 去掉前缀 v / V
        if (trimmed.startsWith("v") || trimmed.startsWith("V")) {
            trimmed = trimmed.substring(1);
        }
        List<Token> out = new ArrayList<>();
        int i = 0;
        while (i < trimmed.length()) {
            char c = trimmed.charAt(i);
            if (Character.isDigit(c)) {
                int start = i;
                while (i < trimmed.length() && Character.isDigit(trimmed.charAt(i))) {
                    i++;
                }
                out.add(new Token(Kind.NUMBER, Long.parseLong(trimmed.substring(start, i))));
            } else if (Character.isLetter(c)) {
                int start = i;
                while (i < trimmed.length() && Character.isLetter(trimmed.charAt(i))) {
                    i++;
                }
                out.add(new Token(Kind.QUALIFIER, qualifierOrder(trimmed.substring(start, i))));
            } else {
                // . - _ 等分隔符跳过
                i++;
            }
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("无法识别的版本号: " + text);
        }
        Version version = new Version(text.trim(), out);
        if (version.tokens.stream().noneMatch(token -> token.isNumber())) {
            throw new IllegalArgumentException("版本号必须至少包含一段数字: " + text);
        }
        return version;
    }

    /** 预发布限定词排在正式版之前；无法识别的限定词排在 rc 之后但在正式版之前。 */
    private static long qualifierOrder(String q) {
        return switch (q.toLowerCase()) {
            case "alpha", "a" -> -60;
            case "beta", "b" -> -50;
            case "milestone", "m" -> -40;
            case "rc", "cr" -> -30;
            case "snapshot" -> -20;
            case "sp", "patch" -> 10;
            default -> -10;
        };
    }

    @Override
    public int compareTo(Version other) {
        int max = Math.max(tokens.size(), other.tokens.size());
        for (int i = 0; i < max; i++) {
            Token a = i < tokens.size() ? tokens.get(i) : Token.ZERO;
            Token b = i < other.tokens.size() ? other.tokens.get(i) : Token.ZERO;
            int cmp = a.compareTo(b);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    @Override
    public String toString() {
        return raw;
    }

    private enum Kind { NUMBER, QUALIFIER }

    private record Token(Kind kind, long value) implements Comparable<Token> {
        static final Token ZERO = new Token(Kind.NUMBER, 0);

        boolean isNumber() {
            return kind == Kind.NUMBER;
        }

        @Override
        public int compareTo(Token o) {
            // 限定词编码为带符号 long（预发布为负、sp 为正），缺省段按 NUMBER 0，直接数值比较即可
            return Long.compare(value, o.value);
        }
    }
}
