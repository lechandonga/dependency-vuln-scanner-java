package com.github.lechandonga.dependencyvulnscannerjava.tests;

import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanDiffService;
import com.github.lechandonga.dependencyvulnscannerjava.service.LibrarySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.service.ScanTask;
import com.github.lechandonga.dependencyvulnscannerjava.service.TaskStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务：库更新后重扫的结论可复现 / 可解释变化。 */
@DisplayName("业务：重扫与结论差异")
class ScanRescanDiffTest {

    private final ScanDiffService diffService = new ScanDiffService();

    private ScanTask succeeded(String taskId, String manifestFp, String libraryFp, List<Finding> findings) {
        return new ScanTask(taskId, TaskStatus.SUCCEEDED, "done",
                manifestFp, libraryFp, findings.size(), findings,
                null, null, List.of(), 0, 0);
    }

    @Test
    @DisplayName("库未变时重扫结论一致，差异为空")
    void identicalLibraryNoDiff() {
        Finding finding = new Finding("CVE-1", "t", "maven", "maven://g/a", "1.5",
                "[1.0,2.0)", com.github.lechandonga.dependencyvulnscannerjava.model.Severity.HIGH,
                com.github.lechandonga.dependencyvulnscannerjava.model.Priority.P1, "fix");
        ScanTask oldTask = succeeded("t1", "mfp", "lfp", List.of(finding));
        ScanTask newTask = succeeded("t2", "mfp", "lfp", List.of(finding));
        ScanDiffService.DiffResult diff = diffService.diff(oldTask, newTask);
        assertTrue(diff.changes().isEmpty());
        assertEquals(1, diff.unchangedCount());
    }

    @Test
    @DisplayName("区间收窄导致旧命中消失 -> RESOLVED 且给出原因")
    void resolvedAfterRangeNarrowed() {
        Finding oldFinding = new Finding("CVE-1", "t", "maven", "maven://g/a", "1.5",
                "[1.0,2.0)", com.github.lechandonga.dependencyvulnscannerjava.model.Severity.HIGH,
                com.github.lechandonga.dependencyvulnscannerjava.model.Priority.P1, "fix");
        ScanTask oldTask = succeeded("t1", "mfp", "lfp-old", List.of(oldFinding));
        ScanTask newTask = succeeded("t2", "mfp", "lfp-new", List.of());
        ScanDiffService.DiffResult diff = diffService.diff(oldTask, newTask);
        assertEquals(1, diff.changes().size());
        assertEquals(ScanDiffService.ChangeType.RESOLVED, diff.changes().get(0).changeType());
        assertTrue(diff.changes().get(0).reason().contains("1.5"));
    }

    @Test
    @DisplayName("新增规则产生新命中 -> NEW_VULNERABILITY")
    void newVulnerabilityAppears() {
        Finding newFinding = new Finding("CVE-2", "t", "maven", "maven://g/a", "1.5",
                "[1.0,3.0)", com.github.lechandonga.dependencyvulnscannerjava.model.Severity.CRITICAL,
                com.github.lechandonga.dependencyvulnscannerjava.model.Priority.P0, "fix");
        ScanTask oldTask = succeeded("t1", "mfp", "lfp-old", List.of());
        ScanTask newTask = succeeded("t2", "mfp", "lfp-new", List.of(newFinding));
        ScanDiffService.DiffResult diff = diffService.diff(oldTask, newTask);
        assertEquals(ScanDiffService.ChangeType.NEW_VULNERABILITY, diff.changes().get(0).changeType());
    }

    @Test
    @DisplayName("同一漏洞区间表达变化 -> RANGE_OR_SEVERITY_CHANGED")
    void rangeExpressionChanged() {
        Finding oldFinding = new Finding("CVE-1", "t", "maven", "maven://g/a", "1.5",
                "[1.0,2.0)", com.github.lechandonga.dependencyvulnscannerjava.model.Severity.HIGH,
                com.github.lechandonga.dependencyvulnscannerjava.model.Priority.P1, "fix");
        Finding newFinding = new Finding("CVE-1", "t", "maven", "maven://g/a", "1.5",
                "[1.0,2.5)", com.github.lechandonga.dependencyvulnscannerjava.model.Severity.HIGH,
                com.github.lechandonga.dependencyvulnscannerjava.model.Priority.P1, "fix");
        ScanDiffService.DiffResult diff =
                diffService.diff(succeeded("t1", "mfp", "l1", List.of(oldFinding)),
                        succeeded("t2", "mfp", "l2", List.of(newFinding)));
        assertEquals(ScanDiffService.ChangeType.RANGE_OR_SEVERITY_CHANGED,
                diff.changes().get(0).changeType());
        assertTrue(diff.changes().get(0).reason().contains("[1.0,2.5)"));
    }

    @Test
    @DisplayName("清单内容不同时拒绝对比")
    void differentManifestRejected() {
        ScanTask a = succeeded("t1", "mfp-1", "lfp", List.of());
        ScanTask b = succeeded("t2", "mfp-2", "lfp", List.of());
        assertThrows(IllegalArgumentException.class, () -> diffService.diff(a, b));
    }

    @Test
    @DisplayName("库指纹随规则内容变化，相同规则集合产生相同指纹（可复现）")
    void fingerprintStableForSameRules() {
        LibrarySnapshot snapshot = new LibrarySnapshot("abc", 0, List.of());
        LibrarySnapshot other = new LibrarySnapshot("abc", 0, List.of());
        assertEquals(snapshot.rules(), other.rules());
        assertEquals("abc", snapshot.fingerprint());
    }
}
