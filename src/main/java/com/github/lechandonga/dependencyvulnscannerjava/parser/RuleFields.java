package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;
import com.github.lechandonga.dependencyvulnscannerjava.model.Priority;
import com.github.lechandonga.dependencyvulnscannerjava.model.Severity;
import com.github.lechandonga.dependencyvulnscannerjava.model.VulnerabilityRule;
import com.github.lechandonga.dependencyvulnscannerjava.version.RangeSyntaxException;
import com.github.lechandonga.dependencyvulnscannerjava.version.VersionRange;

import java.util.Locale;

/** 各漏洞库格式共用的字段校验与规则构建逻辑。 */
final class RuleFields {

    private RuleFields() {
    }

    /**
     * 构建规则，字段问题以 Issue 形式返回；调用方据此拒绝该条目。
     *
     * @return 长度 2：成功时 [VulnerabilityRule, null]，失败时 [null, Issue]
     */
    static Object[] build(String id, String ecosystemRaw, String packageField, String groupField,
                          String rangeRaw, String severityRaw, String priorityRaw,
                          String title, String recommendation, String sourceName, int index) {
        if (id == null || id.isBlank()) {
            return fail(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index, "缺少必填字段 id"));
        }
        id = id.trim();
        String group = groupField == null ? null : groupField.trim();
        String name;
        if (packageField != null && !packageField.isBlank()) {
            String pkg = packageField.trim();
            int colon = pkg.indexOf(':');
            if (colon > 0) {
                group = pkg.substring(0, colon).trim();
                name = pkg.substring(colon + 1).trim();
            } else {
                name = pkg;
            }
        } else {
            name = null;
        }
        if (name == null || name.isBlank()) {
            return fail(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                    "规则 " + id + " 缺少受影响包名 package/group+name"));
        }
        if (rangeRaw == null || rangeRaw.isBlank()) {
            return fail(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                    "规则 " + id + " 缺少受影响版本区间 affectedVersions/range"));
        }
        VersionRange range;
        try {
            range = VersionRange.parse(rangeRaw);
        } catch (RangeSyntaxException e) {
            return fail(new Issue(IssueKinds.VERSION_RANGE_ERROR, sourceName, index,
                    "规则 " + id + " 的版本区间非法: " + e.getMessage()));
        }
        Severity severity = Severity.fromRaw(severityRaw);
        if (severityRaw != null && !severityRaw.isBlank() && severity == Severity.UNKNOWN
                && !isKnownSeverityWord(severityRaw)) {
            return fail(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                    "规则 " + id + " 的 severity 无法识别: " + severityRaw));
        }
        Priority priority = Priority.fromRaw(priorityRaw);
        if (priorityRaw != null && !priorityRaw.isBlank() && priority == null) {
            return fail(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                    "规则 " + id + " 的 priority 无法识别（应为 P0-P3）: " + priorityRaw));
        }
        VulnerabilityRule rule = new VulnerabilityRule(
                id,
                VulnerabilityLibraryParser.normalizeEcosystem(ecosystemRaw),
                group, name,
                rangeRaw.trim(), range,
                severity, priority,
                title, recommendation, sourceName);
        return new Object[]{rule, null};
    }

    private static boolean isKnownSeverityWord(String raw) {
        String s = raw.trim().toLowerCase(Locale.ROOT);
        return switch (s) {
            case "critical", "crit", "严重", "high", "高危", "medium", "moderate", "中危",
                 "low", "低危", "unknown", "未知" -> true;
            default -> false;
        };
    }

    private static Object[] fail(Issue issue) {
        return new Object[]{null, issue};
    }
}
