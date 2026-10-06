package com.github.lechandonga.dependencyvulnscannerjava.core;

import com.github.lechandonga.dependencyvulnscannerjava.core.version.RangeParseException;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.Version;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.VersionRange;
import com.github.lechandonga.dependencyvulnscannerjava.support.BusinessModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessModule("版本区间解析与边界匹配（Maven range 与简化表达式）")
class VersionRangeTest {

    @Nested
    @DisplayName("Maven range 边界开闭")
    class MavenBoundaries {
        @Test
        @DisplayName("[1.0,2.0) 含 1.0 与 1.99，不含 2.0")
        void halfOpen() {
            VersionRange range = VersionRange.parse("[1.0,2.0)");
            assertTrue(range.contains(Version.parse("1.0")));
            assertTrue(range.contains(Version.parse("1.99")));
            assertFalse(range.contains(Version.parse("2.0")));
            assertFalse(range.contains(Version.parse("0.9")));
        }

        @Test
        @DisplayName("[1.0,2.0] 两端都包含")
        void closed() {
            VersionRange range = VersionRange.parse("[1.0,2.0]");
            assertTrue(range.contains(Version.parse("1.0")));
            assertTrue(range.contains(Version.parse("2.0")));
            assertFalse(range.contains(Version.parse("2.0.1")));
        }

        @Test
        @DisplayName("(1.0,2.0) 两端都不包含")
        void open() {
            VersionRange range = VersionRange.parse("(1.0,2.0)");
            assertFalse(range.contains(Version.parse("1.0")));
            assertFalse(range.contains(Version.parse("2.0")));
            assertTrue(range.contains(Version.parse("1.5")));
        }

        @Test
        @DisplayName("预发布边界：[1.0-rc1,1.0) 含 rc2 不含 release")
        void preReleaseBoundary() {
            VersionRange range = VersionRange.parse("[1.0-rc1,1.0)");
            assertTrue(range.contains(Version.parse("1.0-rc1")));
            assertTrue(range.contains(Version.parse("1.0-rc2")));
            assertFalse(range.contains(Version.parse("1.0")));
        }

        @Test
        @DisplayName("[1.5] 精确版本；[1.0,) 下界及以上；(,2.0) 上界以下")
        void exactAndHalfUnbounded() {
            assertTrue(VersionRange.parse("[1.5]").contains(Version.parse("1.5")));
            assertFalse(VersionRange.parse("[1.5]").contains(Version.parse("1.6")));
            assertTrue(VersionRange.parse("[1.0,)").contains(Version.parse("999")));
            assertFalse(VersionRange.parse("[1.0,)").contains(Version.parse("0.9")));
            assertTrue(VersionRange.parse("(,2.0)").contains(Version.parse("0.0.1")));
            assertFalse(VersionRange.parse("(,2.0)").contains(Version.parse("2.0")));
        }
    }

    @Nested
    @DisplayName("简化比较表达式")
    class SimpleExpressions {
        @Test
        @DisplayName(">=1.0,<2.0 与 Maven 半开区间一致")
        void intersection() {
            VersionRange range = VersionRange.parse(">=1.0,<2.0");
            assertTrue(range.contains(Version.parse("1.0")));
            assertFalse(range.contains(Version.parse("2.0")));
        }

        @Test
        @DisplayName("分号同样作为条件分隔符；多个下界取交集")
        void semicolonAndIntersect() {
            VersionRange range = VersionRange.parse(">1.0;>=1.5,<3.0");
            assertFalse(range.contains(Version.parse("1.2")));
            assertTrue(range.contains(Version.parse("1.5")));
            assertFalse(range.contains(Version.parse("3.0")));
        }

        @Test
        @DisplayName("裸版本号等价精确匹配")
        void bareExact() {
            VersionRange range = VersionRange.parse("1.2.3");
            assertTrue(range.contains(Version.parse("1.2.3")));
            assertFalse(range.contains(Version.parse("1.2.4")));
        }

        @Test
        @DisplayName("describe 输出规范化边界")
        void describeStable() {
            assertEquals2("[1.0,2.0)", VersionRange.parse(">=1.0,<2.0").describe());
        }

        private static void assertEquals2(String expected, String actual) {
            org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("畸形区间必须明确报错，不得静默放行")
    class InvalidRanges {
        @Test
        @DisplayName("空串/null 拒绝")
        void blank() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse(""));
            assertThrows(RangeParseException.class, () -> VersionRange.parse(null));
        }

        @Test
        @DisplayName("括号不匹配拒绝")
        void unbalancedBrackets() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse("[1.0,2.0"));
            assertThrows(RangeParseException.class, () -> VersionRange.parse("1.0,2.0)"));
        }

        @Test
        @DisplayName("下界大于上界拒绝")
        void lowerAboveUpper() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse("[2.0,1.0)"));
        }

        @Test
        @DisplayName("上下界相同但边界不都包含（空区间）拒绝")
        void emptyRange() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse("[1.0,1.0)"));
            assertThrows(RangeParseException.class, () -> VersionRange.parse("(1.0,1.0]"));
        }

        @Test
        @DisplayName("区间内版本号非法时拒绝并说明")
        void badVersionInside() {
            RangeParseException ex = assertThrows(RangeParseException.class,
                    () -> VersionRange.parse("[1. 0,2.0)"));
            assertTrue(ex.getMessage().contains("1. 0"));
        }

        @Test
        @DisplayName("不支持的运算符与缺少版本号拒绝")
        void badOperator() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse("~1.0"));
            assertThrows(RangeParseException.class, () -> VersionRange.parse(">="));
        }

        @Test
        @DisplayName("两个不同精确版本的交集拒绝")
        void conflictingExact() {
            assertThrows(RangeParseException.class, () -> VersionRange.parse("=1.0,=2.0"));
        }
    }
}
