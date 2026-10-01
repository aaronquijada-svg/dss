package com.sfe.sign.config;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.net.URI;
import java.net.URISyntaxException;
import org.springframework.util.StringUtils;

public class TsaUriValidator implements ConstraintValidator<ValidTsaUri, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (!StringUtils.hasText(value)) {
            return true;
        }

        try {
            URI uri = new URI(value);
            return uri.isAbsolute()
                    && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null
                    && uri.getRawUserInfo() == null
                    && uri.getRawFragment() == null;
        } catch (URISyntaxException exception) {
            return false;
        }
    }
}

