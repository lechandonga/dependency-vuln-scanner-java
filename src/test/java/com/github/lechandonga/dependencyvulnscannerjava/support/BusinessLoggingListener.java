package com.github.lechandonga.dependencyvulnscannerjava.support;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;

import java.util.Optional;

/**
 * 测试执行日志监听器：以“业务模块 → 用例 → 结果（成功/失败/跳过及原因）”的结构
 * 打印到标准输出，surefire 默认不重定向时可直接在构建日志中看到覆盖情况。
 * 通过 META-INF/services 注册到 JUnit Platform。
 */
public class BusinessLoggingListener implements TestExecutionListener {

    private static final String RESET = "\u001B[0m";
    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";

    private String currentModule;

    @Override
    public void executionStarted(org.junit.platform.launcher.TestIdentifier identifier) {
        Optional<Class<?>> testClass = resolveTestClass(identifier);
        if (testClass.isPresent()) {
            BusinessModule module = findModuleAnnotation(testClass.get());
            String moduleName = module != null ? module.value() : testClass.get().getSimpleName();
            if (identifier.isTest()) {
                if (!moduleName.equals(currentModule)) {
                    currentModule = moduleName;
                    System.out.println();
                    System.out.println(CYAN + "==== 业务模块: " + moduleName + RESET);
                }
                System.out.println("  -- 用例: " + identifier.getDisplayName());
            }
        }
    }

    @Override
    public void executionFinished(org.junit.platform.launcher.TestIdentifier identifier,
                                  TestExecutionResult result) {
        if (!identifier.isTest()) {
            return;
        }
        switch (result.getStatus()) {
            case SUCCESSFUL -> System.out.println(GREEN + "     结果: PASS" + RESET
                    + " - " + identifier.getDisplayName());
            case FAILED -> {
                String reason = result.getThrowable().map(t -> t.getClass().getSimpleName()
                        + ": " + t.getMessage()).orElse("未知原因");
                System.out.println(RED + "     结果: FAIL" + RESET + " - "
                        + identifier.getDisplayName() + "  >>> " + reason);
            }
            case ABORTED -> System.out.println(YELLOW + "     结果: ABORTED" + RESET + " - "
                    + identifier.getDisplayName());
            default -> {
            }
        }
    }

    @Override
    public void executionSkipped(org.junit.platform.launcher.TestIdentifier identifier, String reason) {
        if (identifier.isTest()) {
            System.out.println(YELLOW + "  -- 用例(跳过): " + identifier.getDisplayName()
                    + " 原因: " + reason + RESET);
        }
    }


    private static BusinessModule findModuleAnnotation(Class<?> type) {
        Class<?> current = type;
        while (current != null) {
            BusinessModule module = current.getAnnotation(BusinessModule.class);
            if (module != null) {
                return module;
            }
            current = current.getEnclosingClass();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Optional<Class<?>> resolveTestClass(
            org.junit.platform.launcher.TestIdentifier identifier) {
        return identifier.getSource()
                .filter(source -> source instanceof org.junit.platform.engine.support.descriptor.ClassSource
                        || source instanceof org.junit.platform.engine.support.descriptor.MethodSource)
                .map(source -> {
                    try {
                        String className = source instanceof org.junit.platform.engine.support.descriptor.MethodSource m
                                ? m.getClassName()
                                : ((org.junit.platform.engine.support.descriptor.ClassSource) source).getClassName();
                        return Class.forName(className);
                    } catch (ClassNotFoundException e) {
                        return null;
                    }
                });
    }
}
