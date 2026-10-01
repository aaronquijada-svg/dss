package com.sfe.sign.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record SignatureRequest(
        @NotBlank @Pattern(regexp = ".*\\.pdf$", flags = Pattern.Flag.CASE_INSENSITIVE,
                message = "documentName must identify a PDF document") String documentName,
        @NotNull SignatureMode mode) {
}

