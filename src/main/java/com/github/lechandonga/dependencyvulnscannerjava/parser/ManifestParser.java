package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.dependencyvulnscannerjava.core.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.Version;
import com.github.lechandonga.dependencyvulnscannerjava.core.version.VersionParseException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 依赖清单解析器，支持 JSON / XML / CSV，统一产出 {@link Dependency}。
 * 文件整体无法解析抛全局错误；字段缺失或版本号非法抛条目级错误，携带行号/序号。
 */
public class ManifestParser {

    private static final Set<String> SUPPORTED_TYPES = Set.of("maven", "npm", "pypi");
    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<Dependency> parse(String content, FormatType format, String fileName) {
        return switch (format) {
            case JSON -> parseJson(content, fileName);
            case XML -> parseXml(content, fileName);
            case CSV -> parseCsv(content, fileName);
        };
    }

    private List<Dependency> parseJson(String content, String fileName) {
        JsonNode root;
        try {
            root = objectMapper.readTree(content);
        } catch (com.fasterxml.jackson.core.JacksonException e) {
            throw new ParseException(true, fileName, "JSON 语法错误: " + e.getOriginalMessage());
        } catch (Exception e) {
            throw new ParseException(true, fileName, "JSON 读取错误: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new ParseException(true, fileName, "JSON 根节点必须是对象");
        }
        JsonNode dependencies = root.get("dependencies");
        if (dependencies == null || !dependencies.isArray()) {
            throw new ParseException(true, fileName, "JSON 缺少 dependencies 数组字段");
        }
        String defaultType = textOrNull(root.get("packageType"));
        if (defaultType != null && !SUPPORTED_TYPES.contains(defaultType)) {
            throw new ParseException(true, fileName,
                    "packageType 不支持: " + defaultType + "（允许 maven/npm/pypi）");
        }
        List<Dependency> result = new ArrayList<>();
        for (int i = 0; i < dependencies.size(); i++) {
            JsonNode node = dependencies.get(i);
            String location = fileName + "#dependencies[" + i + "]";
            if (!node.isObject()) {
                throw new ParseException(false, location, "依赖条目必须是 JSON 对象");
            }
            String name = requireText(node, "name", location);
            String versionText = requireText(node, "version", location);
            String group = textOrEmpty(node.get("group"));
            String type = textOrNull(node.get("type"));
            if (type == null) {
                type = defaultType;
            }
            if (type == null) {
                throw new ParseException(false, location, "缺少 type/packageType 字段");
            }
            validateType(type, location);
            Version version;
            try {
                version = Version.parse(versionText);
            } catch (VersionParseException e) {
                throw new ParseException(false, location, "依赖 " + type + ":" + group + ":" + name
                        + " 的版本号非法: " + e.getMessage());
            }
            result.add(new Dependency(group, name, version.toString(), type, location));
        }
        return result;
    }

    private List<Dependency> parseXml(String content, String fileName) {
        Document document;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            document = factory.newDocumentBuilder()
                    .parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new ParseException(true, fileName, "XML 语法错误: " + e.getMessage());
        }
        Element root = document.getDocumentElement();
        if (root == null) {
            throw new ParseException(true, fileName, "XML 缺少根节点");
        }
        String defaultType = root.getAttribute("packageType");
        if (!defaultType.isEmpty() && !SUPPORTED_TYPES.contains(defaultType)) {
            throw new ParseException(true, fileName,
                    "packageType 不支持: " + defaultType + "（允许 maven/npm/pypi）");
        }
        NodeList nodes = root.getElementsByTagName("dependency");
        if (nodes.getLength() == 0) {
            throw new ParseException(true, fileName, "XML 中找不到任何 <dependency> 条目");
        }
        List<Dependency> result = new ArrayList<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            String location = fileName + "#dependency[" + i + "]";
            String name = requireElement(element, "name", location);
            String versionText = requireElement(element, "version", location);
            String group = optionalElement(element, "group");
            String type = optionalElement(element, "type");
            if (type.isEmpty()) {
                type = defaultType;
            }
            if (type.isEmpty()) {
                throw new ParseException(false, location, "缺少 <type>（根节点也未声明 packageType）");
            }
            validateType(type, location);
            Version version;
            try {
                version = Version.parse(versionText);
            } catch (VersionParseException e) {
                throw new ParseException(false, location, "依赖 " + type + ":" + group + ":" + name
                        + " 的版本号非法: " + e.getMessage());
            }
            result.add(new Dependency(group, name, version.toString(), type, location));
        }
        return result;
    }

    private List<Dependency> parseCsv(String content, String fileName) {
        List<Map<String, String>> rows = CsvReader.readWithHeader(content, fileName);
        List<Dependency> result = new ArrayList<>();
        for (Map<String, String> row : rows) {
            String line = row.get("__row__");
            String location = fileName + ":" + line;
            String name = requireColumn(row, "name", location);
            String versionText = requireColumn(row, "version", location);
            String type = row.getOrDefault("type", "");
            if (type.isEmpty()) {
                throw new ParseException(false, location, "缺少 type 列值");
            }
            validateType(type, location);
            String group = row.getOrDefault("group", "");
            Version version;
            try {
                version = Version.parse(versionText);
            } catch (VersionParseException e) {
                throw new ParseException(false, location, "依赖 " + type + ":" + group + ":" + name
                        + " 的版本号非法: " + e.getMessage());
            }
            result.add(new Dependency(group, name, version.toString(), type, location));
        }
        if (result.isEmpty()) {
            throw new ParseException(true, fileName, "CSV 没有任何数据行");
        }
        return result;
    }

    private static void validateType(String type, String location) {
        if (!SUPPORTED_TYPES.contains(type.trim().toLowerCase())) {
            throw new ParseException(false, location,
                    "包管理类型不支持: " + type + "（允许 maven/npm/pypi）");
        }
    }

    private static String requireText(JsonNode node, String field, String location) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) {
            throw new ParseException(false, location, "缺少必填字段: " + field);
        }
        return value.asText().trim();
    }

    private static String textOrNull(JsonNode node) {
        if (node == null || node.isNull() || node.asText().isBlank()) {
            return null;
        }
        return node.asText().trim().toLowerCase();
    }

    private static String textOrEmpty(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        return node.asText().trim();
    }

    private static String requireElement(Element parent, String tag, String location) {
        NodeList list = parent.getElementsByTagName(tag);
        if (list.getLength() == 0 || list.item(0).getTextContent().isBlank()) {
            throw new ParseException(false, location, "缺少必填元素: <" + tag + ">");
        }
        return list.item(0).getTextContent().trim();
    }

    private static String optionalElement(Element parent, String tag) {
        NodeList list = parent.getElementsByTagName(tag);
        return list.getLength() == 0 ? "" : list.item(0).getTextContent().trim();
    }

    private static String requireColumn(Map<String, String> row, String column, String location) {
        String value = row.get(column);
        if (value == null || value.isBlank()) {
            throw new ParseException(false, location, "缺少必填列: " + column);
        }
        return value.trim();
    }
}
