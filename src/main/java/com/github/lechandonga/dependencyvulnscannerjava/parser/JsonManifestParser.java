package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * JSON 清单格式：
 * <pre>
 * { "ecosystem": "maven",
 *   "dependencies": [ {"group": "org.x", "name": "a", "version": "1.2.3"} ] }
 * </pre>
 * 也接受顶层直接是数组的写法。
 */
public class JsonManifestParser implements ManifestParser {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public boolean supports(String filename, String formatHint) {
        return "json".equals(formatHint)
                || (filename != null && filename.toLowerCase(Locale.ROOT).endsWith(".json"));
    }

    @Override
    public ParseOutcome<Dependency> parse(String content, String sourceName) {
        JsonNode root;
        try {
            root = mapper.readTree(content == null ? "" : content);
        } catch (Exception e) {
            return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1,
                    "JSON 整体解析失败: " + e.getMessage()));
        }
        if (root == null || root.isNull() || (!root.isObject() && !root.isArray())) {
            return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1,
                    "JSON 顶层必须是对象或数组"));
        }
        String defaultEcosystem = "maven";
        JsonNode arrayNode;
        if (root.isArray()) {
            arrayNode = root;
        } else {
            JsonNode eco = root.get("ecosystem");
            if (eco != null && eco.isTextual() && !eco.asText().isBlank()) {
                defaultEcosystem = eco.asText().trim();
            }
            arrayNode = root.get("dependencies");
            if (arrayNode == null || !arrayNode.isArray()) {
                return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1,
                        "JSON 对象必须包含 dependencies 数组"));
            }
        }
        List<Dependency> items = new ArrayList<>();
        List<Issue> issues = new ArrayList<>();
        for (int i = 0; i < arrayNode.size(); i++) {
            JsonNode node = arrayNode.get(i);
            if (!node.isObject()) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, i, "依赖条目必须是 JSON 对象"));
                continue;
            }
            String eco = textOr(node, "ecosystem", defaultEcosystem);
            String group = textOr(node, "group", null);
            String name = textOr(node, "name", null);
            String version = textOr(node, "version", null);
            if (name == null || name.isBlank()) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, i, "缺少必填字段 name"));
                continue;
            }
            if (version == null || version.isBlank()) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, i,
                        "依赖 " + name + " 缺少必填字段 version"));
                continue;
            }
            try {
                com.github.lechandonga.dependencyvulnscannerjava.version.Version.parse(version);
            } catch (IllegalArgumentException e) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, i,
                        "依赖 " + name + " 的版本号无法识别: " + version));
                continue;
            }
            items.add(new Dependency(eco, group, name.trim(), version.trim(), sourceName));
        }
        return new ParseOutcome<>(items, issues, false);
    }

    private String textOr(JsonNode node, String field, String fallback) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return fallback;
        }
        if (!v.isTextual()) {
            throw new IllegalArgumentException("字段 " + field + " 必须是字符串");
        }
        return v.asText();
    }
}
