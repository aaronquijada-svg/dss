package com.sfe.sign.api;

import java.util.UUID;

public record ValidationReport(UUID operationId, String status, String signatureLevel, String detail) {
}
