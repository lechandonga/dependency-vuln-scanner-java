package com.github.lechandonga.dependencyvulnscannerjava.scanner;

import com.github.lechandonga.dependencyvulnscannerjava.core.model.Finding;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReportDiffService {

    public ReportDiff diff(ScanReport base, String baseTaskId, ScanReport target, String targetTaskId) {
        Map<String, Finding> baseMap = index(base.findings());
        Map<String, Finding> targetMap = index(target.findings());

        List<ReportDiff.FindingChange> added = new ArrayList<>();
        List<ReportDiff.FindingChange> removed = new ArrayList<>();
        List<ReportDiff.FindingChange> changed = new ArrayList<>();

        for (Map.Entry<String, Finding> entry : targetMap.entrySet()) {
            Finding old = baseMap.get(entry.getKey());
            if (old == null) {
                added.add(new ReportDiff.FindingChange(entry.getKey(), null,
                        ReportDiff.FindingView.of(entry.getValue()), List.of("漏洞库更新后新命中该漏洞")));
                continue;
            }
            List<String> reasons = new ArrayList<>();
            if (!eq(old.priority(), entry.getValue().priority())) {
                reasons.add("处理优先级 " + old.priority() + " → " + entry.getValue().priority());
            }
            if (!eq(old.severity(), entry.getValue().severity())) {
                reasons.add("严重度 " + old.severity() + " → " + entry.getValue().severity());
            }
            if (!eqDouble(old.cvss(), entry.getValue().cvss())) {
                reasons.add("CVSS " + old.cvss() + " → " + entry.getValue().cvss());
            }
            if (!eq(old.matchedRangeExpression(), entry.getValue().matchedRangeExpression())) {
                reasons.add("命中区间 " + old.matchedRangeExpression() + " → "
                        + entry.getValue().matchedRangeExpression());
            }
            if (!eq(old.fixedVersions(), entry.getValue().fixedVersions())) {
                reasons.add("建议修复版本 " + nullToEmpty(old.fixedVersions()) + " → "
                        + nullToEmpty(entry.getValue().fixedVersions()));
            }
            if (!reasons.isEmpty()) {
                changed.add(new ReportDiff.FindingChange(entry.getKey(),
                        ReportDiff.FindingView.of(old),
                        ReportDiff.FindingView.of(entry.getValue()), List.copyOf(reasons)));
            }
        }
        for (Map.Entry<String, Finding> entry : baseMap.entrySet()) {
            if (!targetMap.containsKey(entry.getKey())) {
                removed.add(new ReportDiff.FindingChange(entry.getKey(),
                        ReportDiff.FindingView.of(entry.getValue()), null,
                        List.of("漏洞库更新后该版本不再受影响（区间调整或规则移除）")));
            }
        }
        return new ReportDiff(baseTaskId, targetTaskId, base.vulnerabilityDbHash(),
                target.vulnerabilityDbHash(), List.copyOf(added), List.copyOf(removed), List.copyOf(changed));
    }

    private static Map<String, Finding> index(List<Finding> findings) {
        Map<String, Finding> map = new LinkedHashMap<>();
        for (Finding finding : findings) {
            map.put(finding.vulnId() + "|" + finding.dependencyCoordinate()
                    + "|" + finding.dependencyVersion(), finding);
        }
        return map;
    }

    private static boolean eq(Object a, Object b) {
        return a == null ? b == null : a.equals(b);
    }

    private static boolean eqDouble(Double a, Double b) {
        return a == null ? b == null : (b != null && Double.compare(a, b) == 0);
    }

    private static String nullToEmpty(String text) {
        return text == null ? "" : text;
    }
}
