package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 文本锁文件格式，每行一个依赖：
 * <pre>
 * # ecosystem, group:name:version
 * maven,org.apache.commons:commons-lang3:3.12.0
 * npm,lodash:4.17.20
 * </pre>
 * 生态可省略（默认 maven）；# 开头为注释，空行忽略；格式错误的行逐行拒绝。
 */
public class TextManifestParser implements ManifestParser {

    @Override
    public boolean supports(String filename, String formatHint) {
        return "text".equals(formatHint) || "txt".equals(formatHint)
                || (filename != null && (filename.toLowerCase(Locale.ROOT).endsWith(".txt")
                || filename.toLowerCase(Locale.ROOT).endsWith(".lock")));
    }

    @Override
    public ParseOutcome<Dependency> parse(String content, String sourceName) {
        List<Dependency> items = new ArrayList<>();
        List<Issue> issues = new ArrayList<>();
        String[] lines = (content == null ? "" : content).split("\\R", -1);
        int logicalIndex = 0;
        for (int lineNo = 0; lineNo < lines.length; lineNo++) {
            String line = lines[lineNo].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] firstSplit = line.split(",", 2);
            String ecosystem;
            String body;
            if (firstSplit.length == 2 && looksLikeEcosystem(firstSplit[0].trim())) {
                ecosystem = firstSplit[0].trim();
                body = firstSplit[1].trim();
            } else {
                ecosystem = "maven";
                body = line;
            }
            String[] parts = body.split(":");
            if (parts.length < 2 || parts.length > 3) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName + ":" + (lineNo + 1),
                        logicalIndex, "文本行应为 group:name:version 或 name:version: " + line));
                logicalIndex++;
                continue;
            }
            String group = parts.length == 3 ? parts[0].trim() : null;
            String name = parts.length == 3 ? parts[1].trim() : parts[0].trim();
            String version = parts.length == 3 ? parts[2].trim() : parts[1].trim();
            if (name.isEmpty() || version.isEmpty()) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName + ":" + (lineNo + 1),
                        logicalIndex, "名称或版本为空: " + line));
                logicalIndex++;
                continue;
            }
            try {
                com.github.lechandonga.dependencyvulnscannerjava.version.Version.parse(version);
            } catch (IllegalArgumentException e) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName + ":" + (lineNo + 1),
                        logicalIndex, name + " 的版本号无法识别: " + version));
                logicalIndex++;
                continue;
            }
            items.add(new Dependency(ecosystem, group, name, version, sourceName));
            logicalIndex++;
        }
        return new ParseOutcome<>(items, issues, false);
    }

    private boolean looksLikeEcosystem(String token) {
        if (token.contains(":")) {
            return false;
        }
        return switch (token.toLowerCase(Locale.ROOT)) {
            case "maven", "npm", "pypi", "gem", "golang", "nuget" -> true;
            default -> false;
        };
    }
}
