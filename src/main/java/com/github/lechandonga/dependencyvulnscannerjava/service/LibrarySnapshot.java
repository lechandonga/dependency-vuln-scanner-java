package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.model.VulnerabilityRule;

import java.util.Comparator;
import java.util.List;

/**
 * 某一时刻漏洞库的不可变快照。扫描过程中即使库被重新加载，
 * 进行中的任务仍使用自己拿到的快照，结论确定且可复现。
 *
 * @param fingerprint 规则内容指纹（规则排序后计算），用于重扫对比
 * @param loadedAt    加载时间戳
 * @param rules       已排序、去重的规则
 */
public record LibrarySnapshot(String fingerprint, long loadedAt, List<VulnerabilityRule> rules) {

    public static final Comparator<VulnerabilityRule> RULE_ORDER =
            Comparator.comparing(VulnerabilityRule::coordinate)
                    .thenComparing(VulnerabilityRule::rawRange)
                    .thenComparing(VulnerabilityRule::id);

    public LibrarySnapshot {
        rules = List.copyOf(rules);
    }
}
