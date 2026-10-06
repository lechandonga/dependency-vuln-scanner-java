package com.github.lechandonga.dependencyvulnscannerjava.web;

import org.springframework.http.HttpStatus;

public class ApiException extends RuntimeException {

    private final String errorCode;
    private final HttpStatus status;
    private final String location;

    public ApiException(String errorCode, String message, HttpStatus status) {
        this(errorCode, message, status, null);
    }

    public ApiException(String errorCode, String message, HttpStatus status, String location) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
        this.location = location;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getLocation() {
        return location;
    }
}
