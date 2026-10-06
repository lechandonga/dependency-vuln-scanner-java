package com.github.lechandonga.dependencyvulnscannerjava.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注一个测试类覆盖的业务模块，执行日志按模块分组输出。
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface BusinessModule {
    String value();
}
