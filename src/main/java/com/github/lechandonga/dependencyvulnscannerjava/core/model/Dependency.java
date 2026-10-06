package com.github.lechandonga.dependencyvulnscannerjava.core.model;

/**
 * 内部统一模型：一条被扫描的依赖。
 *
 * @param group    组织/命名空间，如 Maven groupId、npm scope，可为空但不能为 null
 * @param name     组件名，必填
 * @param version  声明版本，必填且必须能解析为版本号
 * @param type     包管理类型：maven / npm / pypi，未知类型在解析阶段拒绝
 * @param source   来源文件名与行号等定位信息，仅用于错误报告
 */
public record Dependency(String group, String name, String version, String type, String source) {

    public String coordinate() {
        return group == null || group.isEmpty() ? name : group + ":" + name;
    }
}
