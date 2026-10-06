package com.github.lechandonga.dependencyvulnscannerjava.tests.support;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Deque;

/**
 * 业务化测试日志：按测试类（业务模块）分组，打印每个用例的结果，
 * 最后输出业务覆盖汇总，方便从日志看出“覆盖了哪些业务、哪些用例、结果如何”。
 */
public class BusinessTestReporter implements TestExecutionListener {

    private static final String PREFIX = "\n==================== 业务测试报告 ====================";

    private final Map<String, BusinessStats> businesses = new LinkedHashMap<>();
    private final Map<String, String> containerToBusiness = new LinkedHashMap<>();

    private record BusinessStats(int passed, int failed, int skipped) {
        BusinessStats plus(TestExecutionResult.Status status) {
            return switch (status) {
                case SUCCESSFUL -> new BusinessStats(passed + 1, failed, skipped);
                case FAILED, ABORTED -> new BusinessStats(passed, failed + 1, skipped);
            };
        }

        BusinessStats skip() {
            return new BusinessStats(passed, failed, skipped + 1);
        }
    }

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        System.out.println(PREFIX);
        System.out.println("开始执行，业务模块：");
        for (TestIdentifier root : testPlan.getRoots()) {
            Deque<TestIdentifier> stack = new ArrayDeque<>(testPlan.getChildren(root));
            while (!stack.isEmpty()) {
                TestIdentifier container = stack.pop();
                if (container.isTest()) {
                    continue;
                }
                registerContainer(testPlan, container);
                stack.addAll(testPlan.getChildren(container));
            }
        }
        businesses.keySet().forEach(name -> System.out.println("  - " + name));
        System.out.println("======================================================");
    }

    private void registerContainer(TestPlan testPlan, TestIdentifier container) {
        boolean hasTestDescendant = testPlan.getDescendants(container).stream()
                .anyMatch(TestIdentifier::isTest);
        if (!hasTestDescendant) {
            return;
        }
        String legacy = container.getLegacyReportingName();
        boolean isTestClass = container.isTest()
                || legacy.endsWith("Test") || legacy.endsWith("Tests")
                || legacy.contains("Test$") || legacy.contains("Tests$");
        if (isTestClass) {
            String business = businessName(container);
            businesses.putIfAbsent(business, new BusinessStats(0, 0, 0));
            containerToBusiness.put(container.getUniqueId(), business);
        }
    }

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        if (testIdentifier.isTest()) {
            System.out.println("[用例开始] " + businessOf(testIdentifier) + " > " + testIdentifier.getDisplayName());
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult result) {
        if (!testIdentifier.isTest()) {
            return;
        }
        String business = businessOf(testIdentifier);
        String mark = switch (result.getStatus()) {
            case SUCCESSFUL -> "PASS";
            case FAILED -> "FAIL";
            case ABORTED -> "ABORT";
        };
        String detail = result.getThrowable().map(t -> " -> " + t.getMessage()).orElse("");
        System.out.println("[" + mark + "] " + business + " > " + testIdentifier.getDisplayName() + detail);
        businesses.computeIfPresent(business, (key, stats) -> stats.plus(result.getStatus()));
    }

    @Override
    public void executionSkipped(TestIdentifier testIdentifier, String reason) {
        if (testIdentifier.isTest()) {
            String business = businessOf(testIdentifier);
            System.out.println("[SKIP] " + business + " > " + testIdentifier.getDisplayName() + " (" + reason + ")");
            businesses.computeIfPresent(business, (key, stats) -> stats.skip());
        }
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        System.out.println(PREFIX);
        System.out.println("业务模块覆盖汇总：");
        int totalPass = 0;
        int totalFail = 0;
        int totalSkip = 0;
        for (Map.Entry<String, BusinessStats> entry : businesses.entrySet()) {
            BusinessStats stats = entry.getValue();
            totalPass += stats.passed();
            totalFail += stats.failed();
            totalSkip += stats.skipped();
            System.out.printf("  %-28s 通过=%d 失败=%d 跳过=%d%n",
                    entry.getKey(), stats.passed(), stats.failed(), stats.skipped());
        }
        System.out.printf("合计：业务=%d，通过=%d，失败=%d，跳过=%d%n",
                businesses.size(), totalPass, totalFail, totalSkip);
        System.out.println("======================================================");
    }

    private String businessOf(TestIdentifier test) {
        String uid = test.getUniqueId();
        return containerToBusiness.keySet().stream()
                .filter(uid::startsWith)
                .sorted((a, b) -> b.length() - a.length())
                .map(containerToBusiness::get)
                .findFirst()
                .orElse("未分组");
    }

    private String businessName(TestIdentifier container) {
        String legacy = container.getLegacyReportingName();
        String simple = legacy.contains("$") ? legacy.substring(0, legacy.indexOf('$')) : legacy;
        int dot = simple.lastIndexOf('.');
        if (dot >= 0) {
            simple = simple.substring(dot + 1);
        }
        simple = simple.replaceAll("Test$", "").replaceAll("Tests$", "");
        return "业务：" + simple.replaceAll("([a-z])([A-Z])", "$1 $2");
    }
}
