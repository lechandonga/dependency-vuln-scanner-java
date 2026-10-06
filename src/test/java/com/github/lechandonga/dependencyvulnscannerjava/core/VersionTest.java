package com.github.lechandonga.dependencyvulnscannerjava.core;

import com.github.lechandonga.dependencyvulnscannerjava.core.version.Version;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.VersionParseException;
import com.github.lechandonga.dependencyvulnscannerjava.support.BusinessModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessModule("版本号解析与比较（Maven 兼容、确定性）")
class VersionTest {

    @Nested
    @DisplayName("数值段按数值比较，末尾零规整")
    class NumericComparison {
        @Test
        @DisplayName("1.0 与 1 等价；1.0.0 与 1 等价")
        void trailingZerosEqual() {
            assertEquals(0, Version.parse("1.0").compareTo(Version.parse("1")));
            assertEquals(0, Version.parse("1.0.0").compareTo(Version.parse("1")));
        }

        @Test
        @DisplayName("1.10 > 1.9（按数值而非字典序）")
        void numericNotLexicographic() {
            assertTrue(Version.parse("1.10").compareTo(Version.parse("1.9")) > 0);
        }

        @Test
        @DisplayName("2.0 > 1.99.99")
        void majorWins() {
            assertTrue(Version.parse("2.0").compareTo(Version.parse("1.99.99")) > 0);
        }

        @Test
        @DisplayName("1 与 1.0 hashCode 一致")
        void hashCodeStable() {
            assertEquals(Version.parse("1").hashCode(), Version.parse("1.0").hashCode());
        }
    }

    @Nested
    @DisplayName("限定符排序与预发布边界")
    class QualifierOrder {
        @Test
        @DisplayName("alpha < beta < milestone(m) < rc < snapshot < release < sp")
        void qualifierChain() {
            String[] ordered = {"1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc",
                    "1.0-snapshot", "1.0", "1.0-sp"};
            for (int i = 0; i < ordered.length - 1; i++) {
                assertTrue(Version.parse(ordered[i]).compareTo(Version.parse(ordered[i + 1])) < 0,
                        ordered[i] + " 应当小于 " + ordered[i + 1]);
            }
        }

        @Test
        @DisplayName("别名归一：a=alpha, b=beta, cr=rc, ga/final/release=空")
        void aliasNormalization() {
            assertEquals(0, Version.parse("1.0-a").compareTo(Version.parse("1.0-alpha")));
            assertEquals(0, Version.parse("1.0-cr").compareTo(Version.parse("1.0-rc")));
            assertEquals(0, Version.parse("1.0-ga").compareTo(Version.parse("1.0")));
            assertEquals(0, Version.parse("1.0-final").compareTo(Version.parse("1")));
        }

        @Test
        @DisplayName("1.0-rc1 < 1.0-rc2 < 1.0")
        void rcCandidatesBeforeRelease() {
            assertTrue(Version.parse("1.0-rc1").compareTo(Version.parse("1.0-rc2")) < 0);
            assertTrue(Version.parse("1.0-rc2").compareTo(Version.parse("1.0")) < 0);
        }

        @Test
        @DisplayName("数字字母混合段：1-sp.1 > 1-sp（后续数字段保留）")
        void mixedSegments() {
            assertTrue(Version.parse("1-sp.1").compareTo(Version.parse("1-sp")) > 0);
            assertTrue(Version.parse("1.0-sp").compareTo(Version.parse("1.0")) > 0);
        }
    }

    @Nested
    @DisplayName("非法版本必须被拒绝")
    class InvalidVersions {
        @Test
        @DisplayName("空串/null 抛 VersionParseException")
        void blank() {
            assertThrows(VersionParseException.class, () -> Version.parse(""));
            assertThrows(VersionParseException.class, () -> Version.parse("   "));
            assertThrows(VersionParseException.class, () -> Version.parse(null));
        }

        @Test
        @DisplayName("含空白字符的版本被拒绝")
        void whitespace() {
            assertThrows(VersionParseException.class, () -> Version.parse("1. 2"));
        }

        @Test
        @DisplayName("含非法字符（逗号/括号等区间符号）的版本被拒绝")
        void illegalChars() {
            assertThrows(VersionParseException.class, () -> Version.parse("1.0,2.0"));
            assertThrows(VersionParseException.class, () -> Version.parse("[1.0]"));
        }
    }
}
