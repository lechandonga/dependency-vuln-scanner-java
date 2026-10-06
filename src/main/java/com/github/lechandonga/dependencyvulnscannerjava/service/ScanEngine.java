package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Finding;
import com.github.lechandonga.dependencyvulnscannerjava.model.VulnerabilityRule;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 匹配引擎（纯函数，无状态）：
 * <ul>
 *   <li>按规范化坐标匹配生态+包，版本落入区间即命中；</li>
 *   <li>同一依赖对同一漏洞编号最多产生一条结论（区间并集/重复规则不重复出结论）；</li>
 *   <li>结论按确定顺序排序，相同输入+相同快照必然得到相同输出。</li>
 * </ul>
 */
@Component
public class ScanEngine {

    static final Comparator<Finding> FINDING_ORDER =
            Comparator.comparing(Finding::priority)
                    .thenComparing(Finding::vulnerabilityId)
                    .thenComparing(Finding::coordinate)
                    .thenComparing(Finding::dependencyVersion);

    public List<Finding> scan(List<Dependency> dependencies, LibrarySnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        for (Dependency dependency : dependencies) {
            // 同一漏洞编号即使在库内有多条（重叠）规则，对同一依赖版本也只产生一条结论。
            Set<String> matchedIds = new HashSet<>();
            for (VulnerabilityRule rule : snapshot.rules()) {
                if (!rule.coordinate().equals(dependency.coordinate())) {
                    continue;
                }
                if (!rule.range().contains(dependency.version())) {
                    continue;
                }
                if (!matchedIds.add(rule.id())) {
                    continue;
                }
                findings.add(new Finding(
                        rule.id(),
                        rule.title(),
                        rule.ecosystem(),
                        dependency.coordinate(),
                        dependency.version(),
                        rule.rawRange(),
                        rule.severity(),
                        rule.effectivePriority(),
                        rule.recommendation()));
            }
        }
        findings.sort(FINDING_ORDER);
        return List.copyOf(findings);
    }

    /** 依赖清单也做坐标+版本去重，保证同一条依赖不被重复评估。 */
    public List<Dependency> normalizeDependencies(List<Dependency> raw) {
        List<Dependency> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Dependency dependency : raw) {
            String key = dependency.coordinate() + "@" + dependency.version();
            if (seen.add(key)) {
                out.add(dependency);
            }
        }
        out.sort(Comparator.comparing(Dependency::coordinate).thenComparing(Dependency::version));
        return List.copyOf(out);
    }
}
