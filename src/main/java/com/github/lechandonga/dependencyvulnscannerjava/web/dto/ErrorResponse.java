package com.github.lechandonga.dependencyvulnscannerjava.web.dto;

import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;

import java.util.List;

/** 统一错误响应：type 区分错误大类，issues 给出逐条定位。 */
public record ErrorResponse(String error, String type, String message, List<Issue> issues) {
}
