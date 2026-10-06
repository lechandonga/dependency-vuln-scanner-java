package com.github.lechandonga.dependencyvulnscannerjava.core.version;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 确定性的 Maven 风格语义版本实现，规则对标 Maven 的
 * {@code org.apache.maven.artifact.versioning.ComparableVersion}：
 * <ul>
 *   <li>{@code .} 与 {@code -}（含 {@code _}、{@code +}）都是分隔符；数字/字母切换也自动分段，
 *       因此 {@code rc1} 整体作为限定符字符串（与 Maven 一致）；</li>
 *   <li>数字段按数值比较，{@code 1} 与 {@code 1.0} 等价（末尾零被规整）；</li>
 *   <li>限定符排序为
 *       {@code alpha(a) &lt; beta(b) &lt; milestone(m) &lt; rc(cr) &lt; snapshot &lt; release(空/ga/final) &lt; sp}，
 *       未知限定符按字典序排在 release 之前；</li>
 *   <li>比较时缺失段补 null：非零数字段 &gt; null；除 release(空) 外的限定符 &lt; null；</li>
 *   <li>纯函数解析，结果只取决于输入字符串。</li>
 * </ul>
 */
public final class Version implements Comparable<Version> {

    private final String raw;
    private final String canonical;
    private final List<Item> items;

    private Version(String raw, String canonical, List<Item> items) {
        this.raw = raw;
        this.canonical = canonical;
        this.items = List.copyOf(items);
    }

    public static Version parse(String text) {
        if (text == null) {
            throw new VersionParseException("版本号不能为 null");
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            throw new VersionParseException("版本号不能为空");
        }
        if (trimmed.chars().anyMatch(Character::isWhitespace)) {
            throw new VersionParseException("版本号不能包含空白字符: '" + text + "'");
        }
        if (!trimmed.matches("[A-Za-z0-9.\\-_+*]+")) {
            throw new VersionParseException("版本号包含非法字符: '" + text + "'");
        }

        List<Item> parsed = new ArrayList<>();
        String normalized = trimmed.replace('_', '-').replace('+', '-');
        int index = 0;
        while (index < normalized.length()) {
            char c = normalized.charAt(index);
            if (c == '.' || c == '-') {
                index++;
                continue;
            }
            int start = index;
            boolean digit = Character.isDigit(c);
            while (index < normalized.length()) {
                char cur = normalized.charAt(index);
                if (cur == '.' || cur == '-') {
                    break;
                }
                if (Character.isDigit(cur) != digit) {
                    break;
                }
                index++;
            }
            String token = normalized.substring(start, index);
            if (digit) {
                parsed.add(new NumberItem(Long.parseLong(token)));
            } else {
                parsed.add(new QualifierItem(token));
            }
        }

        // 规整规则（对齐 Maven）：末尾连续零数字段删除；
        // release 空限定符仅当位于末尾（其后没有数字段，如 1-ga）时删除。
        // 注意 1-sp.1 解析为 [1, "sp", 1]，末尾的 1 不能删；
        // 而 1-ga.1 解析为 [1, "", 1]，空限定符在中间是真实分段，同样保留。
        while (!parsed.isEmpty()) {
            Item last = parsed.get(parsed.size() - 1);
            if (last instanceof NumberItem n && n.value() == 0) {
                parsed.remove(parsed.size() - 1);
            } else {
                break;
            }
        }
        if (!parsed.isEmpty()) {
            Item last = parsed.get(parsed.size() - 1);
            if (last instanceof QualifierItem q && q.isRelease()) {
                parsed.remove(parsed.size() - 1);
            }
        }
        if (parsed.isEmpty()) {
            parsed.add(new NumberItem(0));
        }
        return new Version(trimmed, toCanonical(parsed), parsed);
    }

    private static String toCanonical(List<Item> items) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Item item : items) {
            if (item instanceof NumberItem n) {
                if (!first) {
                    sb.append('.');
                }
                sb.append(n.value());
            } else if (item instanceof QualifierItem q) {
                if (!q.isRelease()) {
                    sb.append('-').append(q.name());
                }
            }
            first = false;
        }
        return sb.toString();
    }

    /** 规范化形式，用于判断 "1" 与 "1.0" 这类书写不同但语义相同的版本。 */
    public String canonical() {
        return canonical;
    }

    @Override
    public int compareTo(Version other) {
        int max = Math.max(items.size(), other.items.size());
        for (int i = 0; i < max; i++) {
            Item left = i < items.size() ? items.get(i) : Item.NULL;
            Item right = i < other.items.size() ? other.items.get(i) : Item.NULL;
            int cmp = left.compareItem(right);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Version v && compareTo(v) == 0;
    }

    @Override
    public int hashCode() {
        return canonical.hashCode();
    }

    @Override
    public String toString() {
        return raw;
    }

    private abstract static class Item {
        static final Item NULL = new NullItem();

        abstract int compareItem(Item other);

        abstract boolean isTrailingNeutral();
    }

    private static final class NumberItem extends Item {
        private final long value;

        NumberItem(long value) {
            this.value = value;
        }

        long value() {
            return value;
        }

        @Override
        int compareItem(Item other) {
            if (other instanceof NumberItem n) {
                return Long.compare(value, n.value);
            }
            if (other instanceof QualifierItem) {
                return 1; // 数字段大于任意限定符，例如 1-1 > 1-ga
            }
            // 与缺失段比较：零等于缺失，非零大于缺失（1.5 > 1）
            return value == 0 ? 0 : 1;
        }

        @Override
        boolean isTrailingNeutral() {
            return value == 0;
        }
    }

    private static final class QualifierItem extends Item {
        private static final String[][] ALIASES = {
                {"a", "alpha"}, {"b", "beta"}, {"m", "milestone"},
                {"cr", "rc"}, {"ga", ""}, {"final", ""}, {"release", ""}
        };

        private final String name;

        QualifierItem(String name) {
            String lower = name.toLowerCase(Locale.ROOT);
            for (String[] alias : ALIASES) {
                if (alias[0].equals(lower)) {
                    lower = alias[1];
                    break;
                }
            }
            this.name = lower;
        }

        String name() {
            return name;
        }

        boolean isRelease() {
            return name.isEmpty();
        }

        private int order() {
            return switch (name) {
                case "alpha" -> 0;
                case "beta" -> 1;
                case "milestone" -> 2;
                case "rc" -> 3;
                case "snapshot" -> 4;
                case "" -> 5;
                case "sp" -> 6;
                default -> 7;
            };
        }

        @Override
        int compareItem(Item other) {
            if (other instanceof QualifierItem q) {
                int cmp = Integer.compare(order(), q.order());
                if (cmp != 0) {
                    return cmp;
                }
                return order() == 7 ? name.compareTo(q.name) : 0;
            }
            if (other instanceof NumberItem) {
                return -1; // 限定符小于数字段
            }
            // 与缺失段比较（对齐 Maven StringItem）：
            // release(空) 等于缺失；sp 特殊地大于缺失（1-sp > 1）；其余限定符小于缺失
            if (name.isEmpty()) {
                return 0;
            }
            return "sp".equals(name) ? 1 : -1;
        }

        @Override
        boolean isTrailingNeutral() {
            return name.isEmpty();
        }
    }

    private static final class NullItem extends Item {
        @Override
        int compareItem(Item other) {
            if (other == this) {
                return 0;
            }
            return -other.compareItem(this);
        }

        @Override
        boolean isTrailingNeutral() {
            return false;
        }
    }
}
