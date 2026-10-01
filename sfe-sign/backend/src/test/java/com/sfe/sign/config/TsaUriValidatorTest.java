package com.sfe.sign.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TsaUriValidatorTest {

    private final TsaUriValidator validator = new TsaUriValidator();

    @Test
    void acceptsAnApprovedHttpOrHttpsTsaUri() {
        assertThat(validator.isValid("https://timestamp.example.test/api", null)).isTrue();
        assertThat(validator.isValid("http://timestamp.example.test", null)).isTrue();
    }

    @Test
    void acceptsAnUnsetTsaUri() {
        assertThat(validator.isValid(null, null)).isTrue();
        assertThat(validator.isValid(" ", null)).isTrue();
    }

    @Test
    void rejectsUnsafeOrIncompleteTsaUris() {
        assertThat(validator.isValid("ftp://timestamp.example.test", null)).isFalse();
        assertThat(validator.isValid("https://user:secret@timestamp.example.test", null)).isFalse();
        assertThat(validator.isValid("https://timestamp.example.test#fragment", null)).isFalse();
        assertThat(validator.isValid("/timestamp", null)).isFalse();
    }
}
