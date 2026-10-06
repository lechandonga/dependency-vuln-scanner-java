package com.github.lechandonga.dependencyvulnscannerjava.parser;

/** 解析问题类别常量，调用方可据此区分问题类型。 */
public final class IssueKinds {
    /** 整个文件格式不对（非法 JSON/XML/YAML），无法逐条校验。 */
    public static final String FILE_FORMAT_ERROR = "FILE_FORMAT_ERROR";
    /** 条目级问题：必填字段缺失、值非法、坐标不合法等。 */
    public static final String ENTRY_FIELD_ERROR = "ENTRY_FIELD_ERROR";
    /** 版本区间写错（括号不配对、下界大于上界、边界版本非法等）。 */
    public static final String VERSION_RANGE_ERROR = "VERSION_RANGE_ERROR";
    /** 漏洞库内规则编号重复。 */
    public static final String DUPLICATE_RULE_ERROR = "DUPLICATE_RULE_ERROR";

    private IssueKinds() {
    }
}
