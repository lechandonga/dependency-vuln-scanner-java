package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 两次扫描结论对比，用于解释“库更新后重扫，哪条结论因为什么变化”。
 * 对比键为 漏洞编号 + 依赖坐标 + 依赖版本；区间表达式变化会标记为 CHANGED。
 */
@Service
public class ScanDiffService {

    public enum ChangeType {
        /** 旧库未命中、新库新命中。 */
        NEW_VULNERABILITY,
        /** 新库不再命中（规则被删除、区间调整或移除）。 */
        RESOLVED,
        /** 仍命中，但区间/严重程度/优先级表达发生变化。 */
        RANGE_OR_SEVERITY_CHANGED,
        /** 结论完全一致。 */
        UNCHANGED
    }

    public record FindingChange(ChangeType changeType, Finding oldFinding, Finding newFinding, String reason) {
    }

    public record DiffResult(String oldLibraryFingerprint,
                             String newLibraryFingerprint,
                             List<FindingChange> changes,
                             int unchangedCount) {
    }

    public DiffResult diff(ScanTask oldTask, ScanTask newTask) {
        if (oldTask.status() != TaskStatus.SUCCEEDED || newTask.status() != TaskStatus.SUCCEEDED) {
            throw new IllegalArgumentException("只能对比两个已成功完成的扫描任务");
        }
        if (!oldTask.manifestFingerprint().equals(newTask.manifestFingerprint())) {
            throw new IllegalArgumentException("两个任务的清单内容不同，无法做库更新对比");
        }
        Map<String, Finding> oldMap = index(oldTask.findings());
        Map<String, Finding> newMap = index(newTask.findings());
        List<FindingChange> changes = new java.util.ArrayList<>();
        int unchanged = 0;
        for (Map.Entry<String, Finding> entry : newMap.entrySet()) {
            Finding oldFinding = oldMap.get(entry.getKey());
            Finding newFinding = entry.getValue();
            if (oldFinding == null) {
                changes.add(new FindingChange(ChangeType.NEW_VULNERABILITY, null, newFinding,
                        "漏洞库新增规则或区间扩大，版本 " + newFinding.dependencyVersion()
                                + " 新落入 " + newFinding.matchedRange()));
            } else if (!sameExpression(oldFinding, newFinding)) {
                changes.add(new FindingChange(ChangeType.RANGE_OR_SEVERITY_CHANGED, oldFinding, newFinding,
                        "区间由 " + oldFinding.matchedRange() + " 调整为 " + newFinding.matchedRange()
                                + describeSeverityChange(oldFinding, newFinding)));
            } else {
                unchanged++;
            }
        }
        for (Map.Entry<String, Finding> entry : oldMap.entrySet()) {
            if (!newMap.containsKey(entry.getKey())) {
                Finding oldFinding = entry.getValue();
                changes.add(new FindingChange(ChangeType.RESOLVED, oldFinding, null,
                        "漏洞库删除规则或区间收窄，版本 " + oldFinding.dependencyVersion()
                                + " 不再落入 " + oldFinding.matchedRange()));
            }
        }
        changes.sort((a, b) -> {
            Finding anchor = a.newFinding() != null ? a.newFinding() : a.oldFinding();
            Finding anchorB = b.newFinding() != null ? b.newFinding() : b.oldFinding();
            return anchor.vulnerabilityId().compareTo(anchorB.vulnerabilityId());
        });
        return new DiffResult(oldTask.libraryFingerprint(), newTask.libraryFingerprint(),
                List.copyOf(changes), unchanged);
    }

    private Map<String, Finding> index(List<Finding> findings) {
        Map<String, Finding> map = new LinkedHashMap<>();
        for (Finding finding : findings) {
            map.put(key(finding), finding);
        }
        return map;
    }

    private String key(Finding finding) {
        return finding.vulnerabilityId() + "|" + finding.coordinate() + "|" + finding.dependencyVersion();
    }

    private boolean sameExpression(Finding a, Finding b) {
        return a.matchedRange().equals(b.matchedRange())
                && a.severity() == b.severity()
                && a.priority() == b.priority();
    }

    private String describeSeverityChange(Finding a, Finding b) {
        if (a.severity() != b.severity() || a.priority() != b.priority()) {
            return "，严重程度/优先级由 " + a.severity() + "/" + a.priority()
                    + " 调整为 " + b.severity() + "/" + b.priority();
        }
        return "";
    }
}
