package com.github.lechandonga.dependencyvulnscannerjava.model;

import java.util.Locale;
import java.util.Objects;

/**
 * 统一内部依赖模型：无论清单来自 JSON / pom.xml / 文本，解析后都是该对象。
 */
public record Dependency(String ecosystem, String group, String name, String version, String source) {

    public Dependency {
        ecosystem = ecosystem == null || ecosystem.isBlank() ? "maven" : ecosystem.trim().toLowerCase(Locale.ROOT);
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(version, "version");
    }

    /** 生态 + 包坐标，作为匹配与去重的规范化键。 */
    public String coordinate() {
        if (group != null && !group.isBlank()) {
            return ecosystem + "://" + group.trim() + "/" + name.trim();
        }
        return ecosystem + "://" + name.trim();
    }
}
