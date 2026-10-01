package com.sfe.sign.config;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Constraint(validatedBy = TsaUriValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidTsaUri {

    String message() default "must be an absolute HTTP(S) URI without credentials or a fragment";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}

