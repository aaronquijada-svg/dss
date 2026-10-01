package com.sfe.sign.api;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
class ApiExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ApiError invalidRequest(IllegalArgumentException exception) {
        return new ApiError("INVALID_REQUEST", exception.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    ApiError invalidState(IllegalStateException exception) {
        return new ApiError("SIGNING_NOT_COMPLETED", exception.getMessage());
    }
}
