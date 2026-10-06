package com.github.lechandonga.dependencyvulnscannerjava.tests;

import com.github.lechandonga.dependencyvulnscannerjava.version.RangeSyntaxException;
import com.github.lechandonga.dependencyvulnscannerjava.version.Version;
import com.github.lechandonga.dependencyvulnscannerjava.version.VersionRange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：版本号比较与版本区间边界语义。 */
@DisplayName("业务：版本区间边界")
class VersionRangeBoundaryTest {

    @Nested
    @DisplayName("版本号比较顺序确定")
    class VersionOrder {

        @Test
        @DisplayName("数字段按数值比较而非字符串比较")
        void numericComparison() {
            assertTrue(Version.parse("1.10.0").compareTo(Version.parse("1.9.0")) > 0);
            assertEquals(0, Version.parse("1.0").compareTo(Version.parse("1.0.0")));
        }

        @Test
        @DisplayName("预发布版本低于正式版本")
        void prereleaseOrdering() {
            assertTrue(Version.parse("2.0-rc1").compareTo(Version.parse("2.0")) < 0);
            assertTrue(Version.parse("1.0-alpha").compareTo(Version.parse("1.0-beta")) < 0);
        }

        @Test
        @DisplayName("v 前缀与多分隔符可解析")
        void prefixAndSeparators() {
            assertEquals(0, Version.parse("v1.2.3").compareTo(Version.parse("1.2.3")));
            assertEquals(0, Version.parse("1_2_3").compareTo(Version.parse("1.2.3")));
        }
    }

    @Nested
    @DisplayName("开闭区间边界")
    class IntervalBoundary {

        @Test
        @DisplayName("闭区间包含两端边界")
        void closedInterval() {
            VersionRange range = VersionRange.parse("[1.0,2.0]");
            assertTrue(range.contains("1.0"));
            assertTrue(range.contains("2.0"));
            assertTrue(range.contains("1.5"));
        }

        @Test
        @DisplayName("开区间排除两端边界")
        void openInterval() {
            VersionRange range = VersionRange.parse("(1.0,2.0)");
            assertFalse(range.contains("1.0"));
            assertFalse(range.contains("2.0"));
            assertTrue(range.contains("1.0.1"));
        }

        @Test
        @DisplayName("混合开闭区间仅含左边界")
        void halfOpenInterval() {
            VersionRange range = VersionRange.parse("[2.0,2.17.0)");
            assertTrue(range.contains("2.0"));
            assertFalse(range.contains("2.17.0"));
            assertTrue(range.contains("2.16.99"));
        }

        @Test
        @DisplayName("单侧区间：无上界与无下界")
        void oneSided() {
            assertTrue(VersionRange.parse("[2.0,)").contains("99.0"));
            assertFalse(VersionRange.parse("[2.0,)").contains("1.9"));
            assertTrue(VersionRange.parse("(,1.0)").contains("0.9"));
            assertFalse(VersionRange.parse("(,1.0)").contains("1.0"));
        }

        @Test
        @DisplayName("精确版本区间")
        void exactVersion() {
            VersionRange range = VersionRange.parse("[1.5]");
            assertTrue(range.contains("1.5"));
            assertFalse(range.contains("1.5.0"));
        }

        @Test
        @DisplayName("并集区间两段都可命中，间隙不命中")
        void unionIntervals() {
            VersionRange range = VersionRange.parse("[1.0,1.5),[2.0,2.5)");
            assertTrue(range.contains("1.2"));
            assertFalse(range.contains("1.6"));
            assertTrue(range.contains("2.1"));
            assertFalse(range.contains("2.5"));
        }

        @Test
        @DisplayName("星号命中任意版本")
        void anyVersion() {
            VersionRange range = VersionRange.parse("*");
            assertTrue(range.contains("0.0.1-alpha"));
            assertTrue(range.contains("999.999"));
        }
    }

    @Nested
    @DisplayName("区间写法错误必须抛出版本区间异常")
    class InvalidRanges {

        @Test
        @DisplayName("括号不配对")
        void unbalancedBrackets() {
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("[1.0,2.0"));
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("1.0,2.0)"));
        }

        @Test
        @DisplayName("下界大于上界")
        void lowerGreaterThanUpper() {
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("[2.0,1.0)"));
        }

        @Test
        @DisplayName("边界版本号非法")
        void invalidBoundary() {
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("[abc,2.0)"));
        }

        @Test
        @DisplayName("精确版本使用开括号非法")
        void exactWithOpenBracket() {
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("(1.5)"));
        }

        @Test
        @DisplayName("空白区间非法")
        void blankRange() {
            assertThrows(RangeSyntaxException.class, () -> VersionRange.parse("   "));
        }
    }
}
