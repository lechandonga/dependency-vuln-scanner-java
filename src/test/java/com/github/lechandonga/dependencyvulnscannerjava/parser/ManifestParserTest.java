package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.support.BusinessModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@BusinessModule("依赖清单解析（JSON/XML/CSV 统一模型与错误分类）")
class ManifestParserTest {

    private final ManifestParser parser = new ManifestParser();

    @Nested
    @DisplayName("三种格式正常解析并归一")
    class HappyPath {
        @Test
        @DisplayName("JSON：包级 packageType + 条目级字段")
        void json() {
            String content = """
                    {"packageType":"maven","dependencies":[
                      {"group":"org.example","name":"lib-a","version":"1.2.3"},
                      {"group":"","name":"lib-b","version":"2.0","type":"npm"}
                    ]}
                    """;
            List<Dependency> deps = parser.parse(content, FormatType.JSON, "man.json");
            assertEquals(2, deps.size());
            assertEquals("org.example:lib-a", deps.get(0).coordinate());
            assertEquals("maven", deps.get(0).type());
            assertEquals("npm", deps.get(1).type());
        }

        @Test
        @DisplayName("XML：根 packageType 与 <dependency> 条目")
        void xml() {
            String content = """
                    <?xml version="1.0"?>
                    <manifest packageType="pypi">
                      <dependency><name>requests-mini</name><version>1.1</version></dependency>
                    </manifest>
                    """;
            List<Dependency> deps = parser.parse(content, FormatType.XML, "man.xml");
            assertEquals(1, deps.size());
            assertEquals("requests-mini", deps.get(0).name());
            assertEquals("pypi", deps.get(0).type());
        }

        @Test
        @DisplayName("CSV：表头映射，引号字段")
        void csv() {
            String content = "type,group,name,version\nmaven,org.example,lib-a,\"1.2.3\"\n";
            List<Dependency> deps = parser.parse(content, FormatType.CSV, "man.csv");
            assertEquals(1, deps.size());
            assertEquals("1.2.3", deps.get(0).version());
        }
    }

    @Nested
    @DisplayName("文件整体格式错误：全局拒绝（global=true）")
    class GlobalFormatErrors {
        @Test
        @DisplayName("JSON 语法损坏")
        void brokenJson() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("{dependencies:[", FormatType.JSON, "bad.json"));
            assertTrue(ex.isGlobal());
        }

        @Test
        @DisplayName("JSON 缺少 dependencies 数组")
        void missingDeps() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("{\"deps\":[]}", FormatType.JSON, "bad.json"));
            assertTrue(ex.isGlobal());
        }

        @Test
        @DisplayName("XML 标签损坏")
        void brokenXml() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("<manifest><dependency></manifest>",
                            FormatType.XML, "bad.xml"));
            assertTrue(ex.isGlobal());
        }

        @Test
        @DisplayName("XML 禁止 DOCTYPE（防 XXE，本地解析不解析外部实体）")
        void xxeRejected() {
            String content = """
                    <?xml version="1.0"?>
                    <!DOCTYPE manifest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                    <manifest packageType="maven">
                      <dependency><group>&xxe;</group><name>a</name><version>1</version></dependency>
                    </manifest>
                    """;
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse(content, FormatType.XML, "xxe.xml"));
            assertTrue(ex.isGlobal());
        }

        @Test
        @DisplayName("CSV 列数与表头不一致属于全局错误")
        void csvColumnMismatch() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("type,name,version\nmaven,a\n", FormatType.CSV, "bad.csv"));
            assertTrue(ex.isGlobal());
            assertTrue(ex.getMessage().contains("列"));
        }

        @Test
        @DisplayName("CSV 表头重复属于全局错误")
        void csvDuplicateHeader() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("type,type,name\nmaven,m,a\n", FormatType.CSV, "bad.csv"));
            assertTrue(ex.isGlobal());
        }
    }

    @Nested
    @DisplayName("单条记录非法：条目级拒绝（global=false）并带定位")
    class EntryErrors {
        @Test
        @DisplayName("缺少 name 字段，定位到数组下标")
        void missingName() {
            String content = """
                    {"packageType":"maven","dependencies":[{"version":"1.0"}]}
                    """;
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse(content, FormatType.JSON, "man.json"));
            assertFalse(ex.isGlobal());
            assertTrue(ex.getLocation().contains("[0]"));
            assertTrue(ex.getMessage().contains("name"));
        }

        @Test
        @DisplayName("版本号非法，条目级拒绝并显示依赖")
        void badVersion() {
            String content = """
                    {"packageType":"maven","dependencies":[
                      {"group":"g","name":"ok","version":"1.0"},
                      {"group":"g","name":"bad","version":"1,0"}
                    ]}
                    """;
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse(content, FormatType.JSON, "man.json"));
            assertFalse(ex.isGlobal());
            assertTrue(ex.getLocation().contains("[1]"));
            assertTrue(ex.getMessage().contains("版本号非法"));
        }

        @Test
        @DisplayName("不支持的包类型被拒绝")
        void unknownType() {
            String content = """
                    {"dependencies":[{"name":"a","version":"1","type":"rpm"}]}
                    """;
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse(content, FormatType.JSON, "man.json"));
            assertFalse(ex.isGlobal());
        }

        @Test
        @DisplayName("XML 缺少 <version> 定位到条目序号")
        void xmlMissingVersion() {
            String content = """
                    <manifest packageType="maven">
                      <dependency><name>a</name></dependency>
                    </manifest>
                    """;
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse(content, FormatType.XML, "man.xml"));
            assertFalse(ex.isGlobal());
            assertTrue(ex.getMessage().contains("version"));
        }

        @Test
        @DisplayName("CSV 空版本值按行号定位")
        void csvEmptyVersion() {
            ParseException ex = assertThrows(ParseException.class,
                    () -> parser.parse("type,name,version\nmaven,a,\n",
                            FormatType.CSV, "man.csv"));
            assertFalse(ex.isGlobal());
            assertEquals("man.csv:2", ex.getLocation());
        }
    }
}
